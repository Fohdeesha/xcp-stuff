# -*- coding: utf-8 -*-
"""Colour helpers.

Colours only when stdout is a terminal, or when HEALTH_FORCE_COLOR=1. The name avoids
FORCE_COLOR on purpose: node tools (xoa-updater) honour that one, and they would then
colourise output this script parses.
"""

import os
import sys

GREEN = ""
YELLOW = ""
CYAN = ""
RESET = ""


def init(stream=None):
    """Decide once whether this run is coloured. Called from main()."""
    global GREEN, YELLOW, CYAN, RESET
    stream = stream if stream is not None else sys.stdout
    forced = os.environ.get("HEALTH_FORCE_COLOR", "0") == "1"
    try:
        is_tty = bool(stream.isatty())
    except (AttributeError, ValueError):
        is_tty = False
    if is_tty or forced:
        GREEN, YELLOW, CYAN, RESET = "\033[32m", "\033[33m", "\033[36m", "\033[0m"
    else:
        GREEN = YELLOW = CYAN = RESET = ""


def green(text):
    return "%s%s%s" % (GREEN, text, RESET)


def yellow(text):
    return "%s%s%s" % (YELLOW, text, RESET)


def cyan(text):
    return "%s%s%s" % (CYAN, text, RESET)


def strip_ansi(text):
    """Defensive: some tools colourise even when told not to."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] == "\033" and i + 1 < n and text[i + 1] == "[":
            j = i + 2
            while j < n and text[j] not in "ABCDEFGHJKSTfmnsulh":
                j += 1
            i = j + 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out)
