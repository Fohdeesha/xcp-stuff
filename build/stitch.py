# -*- coding: utf-8 -*-
"""Build src/ into the single published health.py.

Dumb on purpose. It concatenates the modules in dependency order, drops the top-level
imports of sibling modules, hoists the stdlib imports, embeds the collector's source as
one string, and appends module-alias objects so `config.X` / `parsers.Y` keep resolving.
It rewrites nothing else.

Two mechanical checks make that honest, and the build fails on either:
  * no two modules may define the same top-level name (the flat namespace is shared, so
    a silent shadow would corrupt whichever module lost)
  * the embedded collector source must sha256-match src/collector.py after a round trip

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


def module_toplevel_names(tree):
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
    return names


def import_time_sibling_refs(tree, siblings):
    """Sibling-module names dereferenced while the module BODY runs.

    The alias objects (`config`, `transport`, ...) are built after every module body has
    executed, so any such reference is a NameError on the artifact and works perfectly
    from src/ - which means no unit test can see it. A default argument is how it gets in:
    `def f(timeout=config.X)` evaluates config.X when the `def` runs, not when f is called.
    Decorators and a class body are import-time too; a function body is not.
    """
    found = set()

    def visit(node, deferred):
        if isinstance(node, ast.Name) and node.id in siblings and not deferred:
            found.add("%s (line %d)" % (node.id, node.lineno))
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            for expr in (list(getattr(node, "decorator_list", []))
                         + [d for d in args.defaults if d is not None]
                         + [d for d in args.kw_defaults if d is not None]):
                visit(expr, deferred)
            for stmt in (node.body if isinstance(node.body, list) else [node.body]):
                visit(stmt, True)
            return
        for child in ast.iter_child_nodes(node):
            visit(child, deferred)

    for stmt in tree.body:
        # split_module drops the module's own `if __name__ == "__main__":`, so whatever it
        # says never reaches the artifact
        if isinstance(stmt, ast.If) and ast.dump(stmt.test).find("__main__") >= 0:
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

    # no two modules may define the same top-level name: after flattening they share one
    # namespace, and the loser would be silently replaced
    owners = {}
    clashes = []
    for name in MODULES:
        for symbol in module_toplevel_names(ast.parse(sources[name])):
            if symbol in owners:
                clashes.append("%s: defined by both %s and %s" % (symbol, owners[symbol], name))
            owners[symbol] = name
    if clashes:
        sys.stderr.write("stitch: name collisions in the flattened namespace:\n  %s\n"
                         % "\n  ".join(clashes))
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
        exported = sorted(n for n in module_toplevel_names(ast.parse(sources[name])))
        aliases.append("%s = _module(%r, %s)" % (name, name, exported))

    alias_block = (
        "# %s\n"
        "# --- module aliases %s\n\n"
        "# The sources are separate modules; stitched together they share one namespace,\n"
        "# so `config.X` and `from colors import green` are given something to resolve\n"
        "# against. Registered in sys.modules too, for the imports inside functions.\n"
        "def _module(name, exported):\n"
        "    import types\n"
        "    module = types.ModuleType(name)\n"
        "    module.__file__ = __file__\n"
        "    for symbol in exported:\n"
        "        setattr(module, symbol, globals()[symbol])\n"
        "    sys.modules[name] = module\n"
        "    return module\n\n\n" % ("=" * 86, "-" * 68)
    ) + "\n".join(aliases) + "\n"

    out = [HEADER, ""]
    out.append("\n".join(sorted(set(imports))))
    out.append("")
    out.extend(blocks)
    # after every block: the aliases copy names out of the flat namespace, so the names
    # have to exist first
    out.append(alias_block)
    out.append('\nif __name__ == "__main__":\n    sys.exit(main())\n')
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

    with io.open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)

    # round-trip check: the embedded text must be byte-identical to the source file
    namespace = {}
    exec(compile(embed_collector(collector), "<embed>", "exec"), namespace)
    if hashlib.sha256(namespace["EMBEDDED"].encode("utf-8")).hexdigest() != \
            hashlib.sha256(collector.encode("utf-8")).hexdigest():
        sys.stderr.write("stitch: embedded collector does not round-trip\n")
        return 1

    ast.parse(text)
    sys.stdout.write("wrote %s (%d lines, %d modules, collector %d bytes)\n"
                     % (OUT, text.count("\n") + 1, len(MODULES), len(collector)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
