# -*- coding: utf-8 -*-
"""How the transport gets hold of the collector's source text.

Running from src/ it is read off disk; in the stitched single-file artifact the build
replaces EMBEDDED with the real text (and checks the sha256 round-trips). Keeping it
behind one function means the transport never has to care which of the two it is.
"""

import os

EMBEDDED = None   # set by build/stitch.py in the published health.py


def collector_source():
    if EMBEDDED is not None:
        return EMBEDDED
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "collector.py")
    f = open(path, "rb")
    try:
        return f.read().decode("utf-8")
    finally:
        f.close()
