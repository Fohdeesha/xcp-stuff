# -*- coding: utf-8 -*-
"""What a collected host looks like to the checks.

Collection and rendering are separate phases here, which the bash script could not do:
every host is gathered first, then the whole report is written. That is what lets the
Pool Status section state reachability before the per-host blocks are printed, and it is
what would let the gathering run concurrently later without moving a line of output.
"""

import config
import parsers
import result


class Host(object):
    """One pool member: what xapi says about it, plus whatever the collector got."""

    def __init__(self, address, uuid="", hostname="", enabled="Unknown",
                 multipathing="Unknown"):
        self.address = address
        self.uuid = uuid
        self.hostname = hostname
        self.enabled = enabled
        self.multipathing = multipathing
        self.payload = None          # the collector document
        self.error = None            # why there isn't one
        self.local_now = None        # our clock when the document arrived
        self.is_master = False

    # -- naming -------------------------------------------------------------------
    @property
    def reachable(self):
        return self.payload is not None

    @property
    def label(self):
        return "%s (%s)" % (self.name, self.address)

    @property
    def name(self):
        if self.payload:
            f = self.fact("hostname")
            if f.ok and f.value:
                return f.value
        return self.hostname or self.address

    # -- facts --------------------------------------------------------------------
    def fact(self, key):
        if self.payload is None:
            return result.Fact(False, error="host was not collected")
        return result.wrap(self.payload, key)

    def memory(self):
        """(total_mb, used_mb) or None. None is a first-class answer, not a zero."""
        f = self.fact("meminfo")
        if not f.ok:
            return None
        parsed = parsers.parse_meminfo(f.value)
        if parsed is None:
            return None
        total_mb, avail_mb = parsed
        used_mb = total_mb - avail_mb if total_mb >= avail_mb else 0
        return (total_mb, used_mb)

    def ntp_state(self):
        f = self.fact("timedatectl")
        if not f.ok:
            return {"ntp": "Unknown", "sync": "Unknown"}
        return parsers.parse_timedatectl(f.value)

    def clock_drift(self):
        """Seconds between this host's clock and ours, or None if unknown.

        Our reference time is taken per host, right when its document arrives, so
        transport latency to earlier hosts cannot accumulate into fake drift.
        """
        f = self.fact("now")
        if not f.ok or self.local_now is None:
            return None
        return abs(self.local_now - f.value)

    def pool_role(self):
        """('master', None) | ('slave', address) | (None, None)."""
        f = self.fact("pool_conf")
        if not f.ok:
            return (None, None)
        return parsers.parse_pool_conf(f.value)

    def pool_conf_text(self):
        f = self.fact("pool_conf")
        return f.value if f.ok else "(unavailable)"


class Pool(object):
    """The pool-level document, gathered from POOL_CMD_HOST."""

    def __init__(self):
        self.payload = {}
        self.error = None

    def fact(self, key):
        node = self.payload.get(key)
        if node is None:
            return result.Fact(False, error="not collected")
        return result.wrap(self.payload, key)

    def networks(self):
        return self.payload.get("networks") or {}

    def xostor_in_use(self):
        f = self.fact("xostor_srs")
        return bool(f.ok and f.value)


def ram_match(hosts):
    """True when every host we could read reports the same dom0 RAM, to the nearest GB.

    Hosts whose memory we could not read are skipped rather than counted as a mismatch:
    unknown is not a difference.
    """
    seen = set()
    for host in hosts:
        mem = host.memory()
        if mem is None:
            continue
        seen.add(int(mem[0] / 1024.0 + 0.5))
    return len(seen) <= 1


def ntp_match(hosts):
    """True when every collected host has NTP on, says it is synchronised, and agrees
    with our clock inside the allowance."""
    for host in hosts:
        if not host.reachable:
            continue
        state = host.ntp_state()
        if state["ntp"] != "yes" or state["sync"] != "yes":
            return False
        drift = host.clock_drift()
        if drift is None or drift > config.TIME_SYNC_ALLOWANCE_SECS:
            return False
    return True
