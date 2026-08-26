# -*- coding: utf-8 -*-
"""Turning Lines into the report.

The -f guard lives here and nowhere else, driven by each Line's status. In the bash
script it was a `[[ "$FILTER_OUTPUT" -eq 0 ]] &&` prefix repeated at ~50 call sites, and
four passing lines were missing it - including 'Yum Patch Level: Reference (Master)',
whose absence made -f show the master's baseline while hiding every slave's Match line,
reading as though the slaves had never been checked. Forgetting a guard is not possible
from here.

--json is the same Lines, written out as a document instead of as text. It is deliberately
not a second renderer with its own idea of what was checked: the same add() records both,
so the two modes cannot drift apart about which checks ran, what they said, or whether the
run flagged.
"""

import json
import sys

import colors
import config
import result


def _as_entry(line):
    """One Line as a document entry.

    'flags' is carried explicitly rather than left for the consumer to derive from the
    status. Whether a yellow line counts against the run is a real rule with real
    exceptions - 'XOSTOR In Use: Yes' and a backslash in the root password are facts, not
    findings - and a monitoring consumer that re-derived it from the colour would get
    those wrong in exactly the direction that raises false alarms.
    """
    entry = {"key": line.key, "value": line.text, "status": line.status,
             "flags": line.flags}
    if line.detail_text:
        entry["detail"] = {"title": line.detail_title, "text": line.detail_text}
    return entry


class Report(object):
    def __init__(self, filter_output=False, stream=None, json_mode=False, meta=None):
        self.filter_output = filter_output
        self.stream = stream if stream is not None else sys.stdout
        self.json_mode = json_mode
        self.meta = meta or {}
        self.flagged = False
        self._host_details = []
        self._pool_details = []
        self._poolconf = []
        self.host_label = None   # which detail bucket the current section writes into
        self._sections = []      # json only: the buckets, in the order the report makes them
        self._section = None

    # -- raw output ---------------------------------------------------------------
    def write(self, text=""):
        """--json puts the document on stdout and nothing else, so the rendered report is
        suppressed at the single point that produces it rather than at every caller."""
        if self.json_mode:
            return
        self.stream.write(text + "\n")

    def write_raw(self, text):
        """Exactly these bytes, no newline added. The pool.conf block carries its own
        spacing, and putting it through write() would silently reshape the report."""
        if self.json_mode:
            return
        self.stream.write(text)

    # -- sections -----------------------------------------------------------------
    def begin_section(self, kind, host=None):
        """Say which part of the report the lines that follow belong to.

        This is also what sets host_label, so the bucket a detail blob is filed under and
        the bucket the document lists a check in are decided in one place and cannot
        disagree.
        """
        self.host_label = "XOA" if kind == "xoa" else (host.label if host is not None else None)
        if not self.json_mode:
            return
        section = {"kind": kind}
        if host is not None:
            section["name"] = host.name
            section["address"] = host.address
            section["master"] = bool(host.is_master)
            section["reachable"] = True
        section["checks"] = []
        self._sections.append(section)
        self._section = section

    def end_section(self):
        self.host_label = None
        self._section = None

    def unreachable_host(self, host):
        """A host we could not collect, recorded with no 'checks' key at all.

        The rendered report gives such a host no block: there is nothing to say about it,
        and an empty block would read as a host that passed everything. That trap is
        sharper in a document a machine walks, where an empty checks list counts as zero
        findings - so the key is absent rather than empty, which cannot be summed.
        """
        if not self.json_mode:
            return
        self._sections.append({"kind": "host", "name": host.name, "address": host.address,
                               "master": bool(host.is_master), "reachable": False,
                               "error": host.error or "not collected"})

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
            # recorded under the same guard, so --json and the rendered report answer
            # 'was this line in the output' identically, -f included
            if self.json_mode and self._section is not None:
                self._section["checks"].append(_as_entry(line))
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
        if self.json_mode and self._section is not None:
            # in the document it belongs to the host it describes, rather than to a
            # separate block at the end that a consumer would have to re-attribute
            self._section["pool_conf"] = first

    # -- tail ---------------------------------------------------------------------
    def print_poolconf_section(self):
        self.blank()
        self.heading("---pool.conf contents---")
        self.write_raw("".join(self._poolconf))

    # The document's shape is fixed here rather than left to follow whatever order the
    # rendered report happens to print its sections in. The XOA section moved to the end
    # of the report - after the hosts it has nothing to do with - and the document did not
    # move with it. Anything not named here still lands, after these, rather than
    # vanishing because someone added a section and not a name.
    SECTION_ORDER = ("xoa", "pool")

    def document(self):
        """The whole run as one JSON-ready object.

        No timestamp: two runs of an unchanged pool should produce the same document, so
        that diffing one against another says something. A consumer that wants to know
        when it read this knows that better than the script does.
        """
        doc = {"script_version": config.SCRIPT_VERSION}
        doc.update(self.meta)
        hosts = []
        buckets = {}
        for section in self._sections:
            body = dict(section)
            kind = body.pop("kind")
            if kind == "host":
                hosts.append(body)
            else:
                buckets[kind] = body
        for kind in ([k for k in self.SECTION_ORDER if k in buckets]
                     + [k for k in buckets if k not in self.SECTION_ORDER]):
            doc[kind] = buckets[kind]
        doc["hosts"] = hosts
        doc["flagged"] = self.flagged
        doc["exit_code"] = 1 if self.flagged else 0
        return doc

    def finish(self):
        """Detail blobs, then the version line, which is the last line of every run.

        It can never flag, so -f prints it too - saying which script produced the report
        above is the entire point of it.
        """
        if self.json_mode:
            # ensure_ascii is the default, but it is stated because it is load-bearing:
            # log excerpts reach here as whatever the host had, and a pure-ASCII document
            # survives any locale a cron job runs under. Escaped characters are still
            # valid JSON and every parser turns them back into the same text.
            self.stream.write(
                json.dumps(self.document(), indent=2, ensure_ascii=True) + "\n")
            return 1 if self.flagged else 0
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
