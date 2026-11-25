# -*- coding: utf-8 -*-
"""Build src/ into the single published health.py.

Dumb on purpose. It concatenates the modules in dependency order, drops the top-level
imports of sibling modules, hoists the stdlib imports, embeds the collector's source as
one string, and appends module-alias objects so `config.X` / `parsers.Y` keep resolving.
It rewrites nothing else.

Mechanical checks make that honest, and the build fails on any of them, before anything
is written (a failed build leaves the previous health.py in place):
  * no two modules may bind the same top-level name - definitions, hoisted stdlib
    imports, and names bound inside top-level if/try/for/with blocks alike - and none may
    bind a name the stitcher itself binds (the flat namespace is shared, so a silent
    shadow would corrupt whichever module lost)
  * no module body may use a sibling before the aliases exist: defaults, decorators,
    annotations, class bodies, and sibling imports nested in a top-level block
  * no top-level sibling import may bind a name the flat namespace lacks
    (`from config import X as Y`, `import config as cfg`, `from config import *`)
  * nothing may import `main`
  * the embedded collector source must sha256-match src/collector.py, read back out of
    the artifact text itself, and that text must parse

The alias objects read the flat namespace live, so a module global rebound at run time
reads the same through `module.NAME` as it does inside the module.

If this ever needs to be clever, the layout is wrong.
"""

import ast
import hashlib
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "src")
OUT = os.path.join(ROOT, "health.py")

# dependency order; `main` last, and it is the only one nothing else imports
MODULES = [
    "config",
    "colors",
    "result",
    "parsers",
    "model",
    "collectorsrc",
    "transport",
    "xoredis",
    "xodb",
    "checks",
    "xoa",
    "report",
    "runcmd",
    "main",
]

HEADER = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# J-Sands / D-Pollak - Vates
#
# XCP-ng / XOA pool health check.
#
#   on XOA:            python3 health.py [-f] [-s] [-n name] [host[:port] [password]]
#   on an XCP-ng host: python3 health.py [-f] [-s] [root_password]
#
# GENERATED FILE - built from src/ by build/stitch.py. Edit the sources, not this.
#
# Runs in two environments, decided by /etc/os-release:
#   XOA  - reaches every host of a pool over ssh (sshpass + xo-server-db)
#   host - runs directly on an XCP-ng/XenServer dom0; this host's commands run locally,
#          the other pool members are reached over ssh when a root password is available
#
# Whatever the environment, every host is asked exactly once: the collector below is
# shipped to it on stdin and answers with one JSON document. It has to parse under
# Python 2.7 as well as 3.6, because 8.2.1 dom0 has no python3 - that constraint applies
# to the collector alone, not to this file, which needs 3.6+.
'''


def read(path):
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


# names the stitcher itself binds in the flat namespace, after every module body has run
RESERVED = {"_module", "_AliasModule"}


def _is_main_guard(node):
    return isinstance(node, ast.If) and ast.dump(node.test).find("__main__") >= 0


def _target_names(target):
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            for name in _target_names(elt):
                yield name
    elif isinstance(target, ast.Starred):
        for name in _target_names(target.value):
            yield name
    # an attribute or subscript target binds no name


def module_bindings(tree, siblings):
    """Every name a module binds while its body runs, as (name, how, line) triples.

    `how` is "import: <statement>" for a stdlib import - two modules importing the same
    thing the same way bind the same object, which is no clash - and "definition" for
    everything else. It walks into top-level if/try/with/for/while blocks, which run at
    import too: `try: from shlex import quote / except ImportError: quote = ...` binds
    `quote`, and so does a tuple unpacking or an annotated assignment. Sibling imports
    bind nothing here - split_module drops them, and the flat namespace already holds
    the very objects they named. A function or class BODY binds nothing at module level.
    """
    found = []

    def imported(node):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in siblings:
                    continue
                if alias.asname:
                    found.append((alias.asname, "import: %s" % alias.name, node.lineno))
                else:
                    # `import os` and `import os.path` both bind the module os
                    top = alias.name.split(".")[0]
                    found.append((top, "import: %s" % top, node.lineno))
        else:
            if node.module in siblings:
                return
            for alias in node.names:
                found.append((alias.asname or alias.name,
                              "import: from %s import %s" % (node.module, alias.name),
                              node.lineno))

    def walk(statements):
        for node in statements:
            if _is_main_guard(node):
                continue
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                found.append((node.name, "definition", node.lineno))
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                imported(node)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    for name in _target_names(target):
                        found.append((name, "definition", node.lineno))
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
                for name in _target_names(node.target):
                    found.append((name, "definition", node.lineno))
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                for name in _target_names(node.target):
                    found.append((name, "definition", node.lineno))
                walk(node.body)
                walk(node.orelse)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        for name in _target_names(item.optional_vars):
                            found.append((name, "definition", node.lineno))
                walk(node.body)
            elif isinstance(node, (ast.If, ast.While)):
                walk(node.body)
                walk(node.orelse)
            elif isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
                walk(node.body)
                for handler in node.handlers:
                    if handler.name:
                        found.append((handler.name, "definition", handler.lineno))
                    walk(handler.body)
                walk(node.orelse)
                walk(node.finalbody)

    walk(tree.body)
    return found


def module_toplevel_names(tree, siblings=()):
    """The names a module defines (imports excluded): what its alias object exports."""
    return {name for name, how, _line in module_bindings(tree, set(siblings))
            if how == "definition"}


def binding_clashes(sources, siblings):
    """Every way two bindings would collide once the modules share one namespace.

    A definition in two modules: the later one silently replaces the earlier. A stdlib
    import in one module and a definition of the same name anywhere: the imports are all
    hoisted to the top, so the definition replaces the import for EVERY module, the one
    that imported it included. Two different imports of one name: the same, in hoisting
    order. A name the stitcher itself binds - a module alias, _module, _AliasModule - is
    reserved: the alias block runs last and would replace it."""
    reserved = (set(siblings) - {"main"}) | RESERVED
    clashes = []
    # the alias block's own imports, which the stitcher adds whatever the modules import
    defined, imports = {}, {"sys": ("import: sys", "the stitcher"),
                            "types": ("import: types", "the stitcher")}
    for module in MODULES:
        for name, how, line in module_bindings(ast.parse(sources[module]), siblings):
            where = "%s line %d" % (module, line)
            if name in reserved:
                clashes.append("%s: bound at %s, but the stitcher binds that name itself"
                               % (name, where))
            if how == "definition":
                other = defined.get(name)
                if other and other[0] != module:
                    clashes.append("%s: defined by both %s and %s" % (name, other[1], where))
                if name in imports:
                    clashes.append("%s: imported at %s and defined at %s"
                                   % (name, imports[name][1], where))
                defined.setdefault(name, (module, where))
            else:
                other = imports.get(name)
                if other and other[0] != how:
                    clashes.append("%s: imported differently at %s and %s"
                                   % (name, other[1], where))
                if name in defined:
                    clashes.append("%s: defined at %s and imported at %s"
                                   % (name, defined[name][1], where))
                imports.setdefault(name, (how, where))
    return clashes


def sibling_import_problems(sources, siblings):
    """Top-level sibling imports the flat namespace cannot honour.

    split_module drops every top-level sibling import, which is right for `import config`
    (the alias object stands in) and `from result import ok` (the flat namespace already
    has `ok`). It is wrong for `from config import X as Y` and `import config as cfg`:
    nothing binds Y or cfg, src/ and every test work, and the artifact raises NameError
    the first time the code runs. `from config import *` cannot be checked at all."""
    problems = []
    for module in MODULES:
        for node in ast.parse(sources[module]).body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in siblings and alias.asname and alias.asname != alias.name:
                        problems.append("%s line %d: import %s as %s"
                                        % (module, node.lineno, alias.name, alias.asname))
            elif isinstance(node, ast.ImportFrom) and node.module in siblings:
                for alias in node.names:
                    if alias.name == "*":
                        problems.append("%s line %d: from %s import *"
                                        % (module, node.lineno, node.module))
                    elif alias.asname and alias.asname != alias.name:
                        problems.append("%s line %d: from %s import %s as %s"
                                        % (module, node.lineno, node.module, alias.name,
                                           alias.asname))
    return problems


def import_time_sibling_refs(tree, siblings):
    """Sibling-module names dereferenced while the module BODY runs.

    The alias objects (`config`, `transport`, ...) are built after every module body has
    executed, so any such reference is a NameError on the artifact and works perfectly
    from src/ - which means no unit test can see it. A default argument is how it gets in:
    `def f(timeout=config.X)` evaluates config.X when the `def` runs, not when f is called.
    Decorators and a class body are import-time too; a function body is not. So are
    annotations - every argument's and the return's are evaluated when the `def` runs,
    exactly like a default. And an import of a sibling that is not one of the top-level
    imports split_module drops (one inside a top-level `try` or `if`) runs at import,
    when sys.modules has no alias for it yet.
    """
    found = set()

    def visit(node, deferred):
        if isinstance(node, ast.Name) and node.id in siblings and not deferred:
            found.add("%s (line %d)" % (node.id, node.lineno))
            return
        if not deferred and isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in siblings:
                    found.add("import %s (line %d)" % (alias.name, node.lineno))
            return
        if not deferred and isinstance(node, ast.ImportFrom) and node.module in siblings:
            found.add("from %s import (line %d)" % (node.module, node.lineno))
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            every_arg = (list(getattr(args, "posonlyargs", [])) + list(args.args)
                         + list(args.kwonlyargs)
                         + [a for a in (args.vararg, args.kwarg) if a is not None])
            for expr in (list(getattr(node, "decorator_list", []))
                         + [d for d in args.defaults if d is not None]
                         + [d for d in args.kw_defaults if d is not None]
                         + [a.annotation for a in every_arg if a.annotation is not None]
                         + [r for r in [getattr(node, "returns", None)] if r is not None]):
                visit(expr, deferred)
            for stmt in (node.body if isinstance(node.body, list) else [node.body]):
                visit(stmt, True)
            return
        for child in ast.iter_child_nodes(node):
            visit(child, deferred)

    for stmt in tree.body:
        # split_module drops the module's own `if __name__ == "__main__":`, so whatever it
        # says never reaches the artifact; and it drops every top-level sibling import
        if _is_main_guard(stmt):
            continue
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            continue
        visit(stmt, False)
    return found


def split_module(source, siblings):
    """(stdlib import lines, body without its own docstring or sibling imports)."""
    tree = ast.parse(source)
    lines = source.splitlines()
    drop = set()
    stdlib_imports = []

    body = list(tree.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        for i in range(body[0].lineno - 1, body[0].end_lineno):
            drop.add(i)
        body = body[1:]

    for node in tree.body:
        # a module's own `if __name__ == "__main__":` block: the stitched file gets one
        # of its own at the very end, after the aliases exist
        if isinstance(node, ast.If) and ast.dump(node.test).find("__main__") >= 0:
            for i in range(node.lineno - 1, node.end_lineno):
                drop.add(i)
            continue
        if isinstance(node, ast.Import):
            keep = []
            for alias in node.names:
                if alias.name in siblings:
                    continue
                keep.append("import %s%s" % (alias.name,
                                             " as %s" % alias.asname if alias.asname else ""))
            stdlib_imports.extend(keep)
            for i in range(node.lineno - 1, node.end_lineno):
                drop.add(i)
        elif isinstance(node, ast.ImportFrom):
            if node.module in siblings:
                for i in range(node.lineno - 1, node.end_lineno):
                    drop.add(i)
            else:
                names = ", ".join(a.name + (" as %s" % a.asname if a.asname else "")
                                  for a in node.names)
                stdlib_imports.append("from %s import %s" % (node.module, names))
                for i in range(node.lineno - 1, node.end_lineno):
                    drop.add(i)

    kept = [line for i, line in enumerate(lines) if i not in drop]
    # strip the coding cookie and any leftover leading blank lines
    while kept and (not kept[0].strip() or kept[0].startswith("# -*- coding")):
        kept.pop(0)
    return stdlib_imports, "\n".join(kept).rstrip() + "\n"


def embed_collector(text):
    """The collector travels as a string, so it must survive being one exactly.

    A RAW triple-single-quoted string: raw so every backslash in the collector's regexes
    and rpm format strings arrives verbatim, and single-quoted because the collector's own
    docstrings use the double form. Readable in the published file, which matters - people
    are entitled to see what this ships to their hosts. Both preconditions are asserted
    here and the result is sha256-checked by the caller.
    """
    if "'''" in text:
        raise SystemExit("collector.py contains ''' and cannot be embedded as a raw "
                         "triple-single-quoted string")
    if text.endswith("\\"):
        raise SystemExit("collector.py ends with a backslash; a raw string cannot")
    return "EMBEDDED = r'''" + text + "'''\n"


def main():
    siblings = set(MODULES)
    sources = {name: read(os.path.join(SRC, name + ".py")) for name in MODULES}

    # no two modules may bind the same top-level name: after flattening they share one
    # namespace, and the loser would be silently replaced
    clashes = binding_clashes(sources, siblings)
    if clashes:
        sys.stderr.write("stitch: name collisions in the flattened namespace:\n  %s\n"
                         % "\n  ".join(clashes))
        return 1

    # ...and no top-level sibling import may need a name the flat namespace lacks
    problems = sibling_import_problems(sources, siblings)
    if problems:
        sys.stderr.write("stitch: sibling imports the stitched file cannot honour (use "
                         "`import module` or the bare name):\n  %s\n" % "\n  ".join(problems))
        return 1

    # ...and no module body may reach into another module: the aliases do not exist yet
    early = []
    for name in MODULES:
        # a module's own name always resolves - it is the flat namespace's own function
        others = siblings - {name}
        for ref in sorted(import_time_sibling_refs(ast.parse(sources[name]), others)):
            early.append("%s: %s used at module level" % (name, ref))
    if early:
        sys.stderr.write("stitch: sibling module used before the aliases exist:\n  %s\n"
                         % "\n  ".join(early))
        return 1

    # ...and nothing may import `main`. It gets no alias object - the name belongs to the
    # function main() in the flat namespace - so `import main` survives the build (the
    # import line is dropped like any other sibling import) and then `main.anything` is an
    # AttributeError on the artifact alone. Every test runs against src/, where main IS a
    # module, so nothing else can see this.
    importers = []
    for name in MODULES:
        if name == "main":
            continue
        for node in ast.walk(ast.parse(sources[name])):
            if isinstance(node, ast.Import) and any(a.name == "main" for a in node.names):
                importers.append("%s (line %d)" % (name, node.lineno))
            elif isinstance(node, ast.ImportFrom) and node.module == "main":
                importers.append("%s (line %d)" % (name, node.lineno))
    if importers:
        sys.stderr.write("stitch: main is a function in the flattened namespace, not a "
                         "module, so it cannot be imported:\n  %s\n"
                         % "\n  ".join(sorted(importers)))
        return 1

    collector = read(os.path.join(SRC, "collector.py"))

    imports = []
    blocks = []
    for name in MODULES:
        mod_imports, body = split_module(sources[name], siblings)
        for line in mod_imports:
            if line not in imports:
                imports.append(line)
        blocks.append("# %s\n# --- %s %s\n\n%s" % ("=" * 86, name, "-" * (82 - len(name)), body))
        if name == "collectorsrc":
            blocks.append(embed_collector(collector))

    aliases = []
    for name in MODULES:
        if name == "main":
            continue           # nothing imports it, and the alias would shadow main()
        exported = sorted(module_toplevel_names(ast.parse(sources[name]), siblings))
        aliases.append("%s = _module(%r, %s)" % (name, name, exported))

    alias_block = (
        "# %s\n"
        "# --- module aliases %s\n\n"
        "# The sources are separate modules; stitched together they share one namespace,\n"
        "# so `config.X` and `from colors import green` are given something to resolve\n"
        "# against. Registered in sys.modules too, for the imports inside functions.\n"
        "#\n"
        "# Read LIVE from the flat namespace, never copied: a module global rebound later\n"
        "# (colors.init() sets the colour codes, xodb caches the db) must read the same\n"
        "# through `colors.YELLOW` as it does inside colors itself - a copy taken here\n"
        "# would go on serving the import-time value on the artifact alone.\n"
        "class _AliasModule(types.ModuleType):\n"
        "    def __init__(self, name, exported):\n"
        "        types.ModuleType.__init__(self, name)\n"
        "        object.__setattr__(self, '_exported', frozenset(exported))\n"
        "        object.__setattr__(self, '__file__', __file__)\n\n"
        "    def __getattr__(self, symbol):\n"
        "        if symbol in self._exported and symbol in globals():\n"
        "            return globals()[symbol]\n"
        "        raise AttributeError('module %%r has no attribute %%r' %% (self.__name__, symbol))\n\n"
        "    def __setattr__(self, symbol, value):\n"
        "        if symbol in self._exported:\n"
        "            globals()[symbol] = value\n"
        "        else:\n"
        "            object.__setattr__(self, symbol, value)\n\n"
        "    def __dir__(self):\n"
        "        return sorted(self._exported)\n\n\n"
        "def _module(name, exported):\n"
        "    module = _AliasModule(name, exported)\n"
        "    sys.modules[name] = module\n"
        "    return module\n\n\n" % ("=" * 86, "-" * 68)
    ) + "\n".join(aliases) + "\n"

    # the alias block needs both, whatever the modules happen to import
    for needed in ("import sys", "import types"):
        if needed not in imports:
            imports.append(needed)

    out = [HEADER, ""]
    out.append("\n".join(sorted(set(imports))))
    out.append("")
    out.extend(blocks)
    # after every block: the aliases copy names out of the flat namespace, so the names
    # have to exist first
    out.append(alias_block)
    out.append('\nif __name__ == "__main__":\n    sys.exit(entry())\n')
    text = "\n\n".join(out)

    # --check: is the committed health.py current? For a pre-commit hook or CI, so a
    # source change cannot land without the artifact it produces.
    if "--check" in sys.argv:
        try:
            current = read(OUT)
        except IOError:
            sys.stderr.write("stitch: %s does not exist; run build/stitch.py\n" % OUT)
            return 1
        if current != text:
            sys.stderr.write("stitch: %s is stale - run build/stitch.py\n" % OUT)
            return 1
        sys.stdout.write("%s is up to date\n" % OUT)
        return 0

    # every check runs on the text about to be written, BEFORE it is: a build that fails
    # must leave the previous health.py in place, not a broken one someone then copies
    # to an appliance
    problem = artifact_problem(text, collector)
    if problem:
        sys.stderr.write("stitch: %s; %s left as it was\n" % (problem, OUT))
        return 1

    tmp = OUT + ".tmp"
    with io.open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.replace(tmp, OUT)
    sys.stdout.write("wrote %s (%d lines, %d modules, collector %d bytes)\n"
                     % (OUT, text.count("\n") + 1, len(MODULES), len(collector)))
    return 0


def artifact_problem(text, collector):
    """Why this artifact text must not be written, or None.

    The round trip is checked on the collector string AS IT SITS IN THE TEXT: exec'ing a
    fresh embed_collector() would prove the embedding function works, not that the
    artifact carries the bytes."""
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return "the stitched file does not parse (%s)" % exc
    embedded = None
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "EMBEDDED"
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            embedded = node.value.value
    if embedded is None:
        return "the stitched file carries no collector string"
    if hashlib.sha256(embedded.encode("utf-8")).hexdigest() != \
            hashlib.sha256(collector.encode("utf-8")).hexdigest():
        return "the embedded collector does not round-trip"
    return None


if __name__ == "__main__":
    sys.exit(main())
