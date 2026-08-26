# -*- coding: utf-8 -*-
"""The one rule this tool exists to keep: never report green off a fact you failed to
establish.

In the bash script that was discipline plus periodic audits, and it broke four times in
ways that took a while to notice. Here it is structural: a check returns a Line, there is
no constructor that produces a green line without a value behind it, and a check that
raises is turned into a yellow Unknown by the runner rather than being skipped.

  OK       green, suppressed by -f, exit-code neutral
  FLAG     yellow, always printed, flags the exit code
  UNKNOWN  yellow, always printed, flags the exit code  (we could not look)
  INFO     always printed, exit-code neutral, colour chosen by the caller
           - for lines with no threshold behind them: Last Booted, Multipathing, ...
"""

import traceback

import colors

OK = "ok"
FLAG = "flag"
UNKNOWN = "unknown"
INFO = "info"


class Line(object):
    """One 'Key: value' line of the report, plus any detail blob it wants printed."""

    __slots__ = ("key", "text", "status", "detail_title", "detail_text", "label")

    def __init__(self, key, text, status, detail_title=None, detail_text=None):
        self.key = key
        self.text = text
        self.status = status
        self.detail_title = detail_title
        self.detail_text = detail_text
        self.label = key + ":"      # a couple of lines pad this for alignment

    @property
    def flags(self):
        return self.status in (FLAG, UNKNOWN)

    @property
    def always_print(self):
        return self.status in (FLAG, UNKNOWN, INFO)

    def render(self):
        return "%s %s" % (self.label, self.text)

    def with_detail(self, title, text):
        self.detail_title = title
        self.detail_text = text
        return self


def ok(key, text):
    return Line(key, colors.green(text), OK)


def flag(key, text, extra=""):
    """A finding. 'extra' is appended outside the colouring, like 'Fail - /var is at 90%'."""
    return Line(key, colors.yellow(text) + extra, FLAG)


def unknown(key, text):
    """We could not establish the fact. Same weight as a finding, different meaning."""
    return Line(key, colors.yellow(text), UNKNOWN)


def info(key, text, color="green"):
    """A fact with no threshold behind it, so it can never flag and always prints."""
    painted = colors.yellow(text) if color == "yellow" else (
        colors.green(text) if color == "green" else text)
    return Line(key, painted, INFO)


def raw(key, text):
    """Uncoloured, exit-code neutral, always printed."""
    return Line(key, text, INFO)


def guard(key, fn, *args, **kwargs):
    """Run a check; turn any escaped exception into a yellow Unknown for that line.

    A check that blows up must not kill the run and must never be silently skipped -
    a skipped line reads as 'not applicable', which is a claim of its own.
    """
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - deliberate: one bad check, one bad line
        import sys
        sys.stderr.write("internal error in %s:\n%s\n" % (key, traceback.format_exc()))
        return unknown(key, "Unknown (internal error: %s)" % exc)


class Fact(object):
    """One value from the collector, or the reason it is missing."""

    __slots__ = ("ok", "value", "error")

    def __init__(self, ok_, value=None, error=None):
        self.ok = ok_
        self.value = value
        self.error = error

    def __repr__(self):
        return "Fact(ok=%r, value=%r, error=%r)" % (self.ok, self.value, self.error)


MISSING = Fact(False, error="not collected")


def wrap(payload, key):
    """Pull one fact out of a collector document."""
    node = payload.get(key)
    if not isinstance(node, dict):
        return Fact(False, error="not collected")
    if node.get("ok"):
        return Fact(True, value=node.get("value"))
    return Fact(False, error=node.get("error") or "unavailable")
