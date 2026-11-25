# -*- coding: utf-8 -*-
"""The stitcher's own checks (audit 2026-11-24, E20-E24).

Every test in this suite runs against src/, where each module is a real module. The
artifact is one flat namespace, so a whole class of mistakes works in every test and
breaks only in health.py - the stitcher is the only thing that can see them, and these
tests pin that it does.
"""

import ast
import importlib.util
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _stitch():
    spec = importlib.util.spec_from_file_location(
        "stitch_under_test", os.path.join(ROOT, "build", "stitch.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


stitch = _stitch()
SIBLINGS = set(stitch.MODULES)


def refs(source):
    return stitch.import_time_sibling_refs(ast.parse(source), SIBLINGS - {"xoa"})


def sources_with(**overrides):
    """Every module empty except the ones given."""
    sources = dict((name, "") for name in stitch.MODULES)
    sources.update(overrides)
    return sources


# --------------------------------------------------------------------------------------
# import-time references (E20)
# --------------------------------------------------------------------------------------

def test_a_default_is_import_time():
    assert refs("def f(x=config.X):\n    pass\n")


def test_an_annotation_is_import_time():
    assert refs("def f(x: config.T):\n    pass\n")
    assert refs("def f() -> config.R:\n    pass\n")
    assert refs("def f(*a: config.T):\n    pass\n")
    assert refs("def f(*, k: config.T = 1):\n    pass\n")


def test_a_function_body_is_not():
    assert not refs("def f():\n    return config.X\n")


def test_a_sibling_import_inside_a_top_level_block_is_import_time():
    """split_module only drops top-level imports; one inside a try runs at import, when
    sys.modules has no alias for it yet."""
    assert refs("try:\n    from config import X\nexcept ImportError:\n    X = 1\n")
    assert refs("if True:\n    import config\n")


def test_a_top_level_sibling_import_is_dropped_not_reported():
    assert not refs("import config\nfrom result import ok\n")


# --------------------------------------------------------------------------------------
# sibling imports the flat namespace cannot honour (E21)
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("line", [
    "from config import X as Y\n",
    "import config as cfg\n",
    "from config import *\n",
])
def test_an_import_that_binds_a_missing_name_fails(line):
    assert stitch.sibling_import_problems(sources_with(xoa=line), SIBLINGS)


def test_plain_sibling_imports_are_fine():
    assert not stitch.sibling_import_problems(
        sources_with(xoa="import config\nfrom result import ok, flag\n"), SIBLINGS)


# --------------------------------------------------------------------------------------
# bindings and clashes (E22)
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize("source, name", [
    ("A, B = 1, 2\n", "B"),
    ("X: int = 3\n", "X"),
    ("if True:\n    def g():\n        pass\n", "g"),
    ("try:\n    from shlex import quote\nexcept ImportError:\n    quote = None\n", "quote"),
    ("for K in range(2):\n    pass\n", "K"),
    ("with open('x') as fh:\n    pass\n", "fh"),
])
def test_every_module_level_binding_is_seen(source, name):
    assert name in [n for n, _how, _line in stitch.module_bindings(ast.parse(source),
                                                                    SIBLINGS)]


def test_a_function_body_binds_nothing_at_module_level():
    names = [n for n, _h, _l in stitch.module_bindings(
        ast.parse("def f():\n    inner = 1\n"), SIBLINGS)]
    assert names == ["f"]


def test_a_tuple_binding_in_two_modules_clashes():
    assert stitch.binding_clashes(sources_with(xoa="A, B = 1, 2\n", report="B = 3\n"),
                                  SIBLINGS)


def test_an_import_and_a_definition_of_one_name_clash():
    """The imports are hoisted above every module, so the def would replace the import
    for the module that imported it too."""
    assert stitch.binding_clashes(
        sources_with(xoa="from os.path import join\n", report="def join():\n    pass\n"),
        SIBLINGS)


def test_two_different_imports_of_one_name_clash():
    assert stitch.binding_clashes(
        sources_with(xoa="from os.path import join\n", report="from shlex import join\n"),
        SIBLINGS)


def test_the_same_import_twice_is_no_clash():
    assert not stitch.binding_clashes(
        sources_with(xoa="import os\nimport os.path\n", report="import os\n"), SIBLINGS)


@pytest.mark.parametrize("source", [
    "config = 1\n", "def _module():\n    pass\n", "_AliasModule = None\n",
    "types = None\n", "def sys():\n    pass\n",
])
def test_a_name_the_stitcher_binds_is_reserved(source):
    assert stitch.binding_clashes(sources_with(xoa=source), SIBLINGS)


def test_the_real_sources_are_clean():
    sources = dict((name, stitch.read(os.path.join(stitch.SRC, name + ".py")))
                   for name in stitch.MODULES)
    assert stitch.binding_clashes(sources, SIBLINGS) == []
    assert stitch.sibling_import_problems(sources, SIBLINGS) == []


# --------------------------------------------------------------------------------------
# the artifact is checked before it is written (E23)
# --------------------------------------------------------------------------------------

def test_a_text_that_does_not_parse_is_refused():
    assert "does not parse" in stitch.artifact_problem("def (:\n", "x")


def test_a_text_without_the_collector_is_refused():
    assert "no collector" in stitch.artifact_problem("X = 1\n", "x")


def test_the_round_trip_is_read_out_of_the_text_itself():
    collector = "print('hi')\n"
    good = "A = 1\n" + stitch.embed_collector(collector)
    assert stitch.artifact_problem(good, collector) is None
    assert "round-trip" in stitch.artifact_problem(good, collector + " ")


# --------------------------------------------------------------------------------------
# the aliases read live (E24) - checked on the real artifact, in a child interpreter so
# its sys.modules entries never replace src/'s in this one
# --------------------------------------------------------------------------------------

PROBE = r"""
import runpy, sys
ns = runpy.run_path(sys.argv[1], run_name="health_probe")
colors = sys.modules["colors"]
config = sys.modules["config"]
before = colors.YELLOW
ns["init"](force_off=False)
after = colors.YELLOW
config.LOCAL_CMD_TIMEOUT = 77
flat = ns["init"].__globals__            # the one namespace every function really reads
print(repr(before), repr(after), flat["LOCAL_CMD_TIMEOUT"],
      "missing" if not hasattr(colors, "no_such_name") else "present")
"""


def test_an_alias_reads_a_rebound_global_live():
    artifact = os.path.join(ROOT, "health.py")
    if not os.path.exists(artifact):
        pytest.skip("health.py not built")
    env = dict(os.environ, HEALTH_FORCE_COLOR="1")
    out = subprocess.check_output([sys.executable, "-c", PROBE, artifact], env=env,
                                  universal_newlines=True)
    before, after, timeout, missing = out.split()
    assert before == "''"
    assert after == repr("\033[33m")
    assert timeout == "77"
    assert missing == "missing"
