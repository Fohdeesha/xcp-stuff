# -*- coding: utf-8 -*-
"""`XOA Plugins`: is anything installed in xo-server that Vates did not ship?

A plugin is a directory under one of xo-server's lookup paths whose name starts
`xo-server-`. It runs inside xo-server, with xo-server's access to every pool, and nothing
in XOA's own tooling ever mentions one it did not install - an `xoa-updater` run does not
name it and `xoa check` does not look. So an appliance can be carrying one with no sign of
it anywhere in a report, which is how a third-party plugin broke a customer's pool
quietly.

The check is a WHITELIST, and these tests are mostly about the consequences of that
choice: an unrecognised name is reported rather than assumed benign, the golden list is
the union of a live source and a built-in one so it does not go stale silently, and a
directory that could not be listed is Unknown rather than "nothing there".
"""

import json
import os

import pytest

import config
import parsers
import result
import xoa


STOCK = ["xo-server-audit", "xo-server-netbox", "xo-server-transport-email"]


def plant(root, name, version="1.0.0", scope=None):
    """One installed plugin, with the package.json npm would have left beside it."""
    directory = root / scope / name if scope else root / name
    directory.mkdir(parents=True)
    if version is not None:
        (directory / "package.json").write_text(json.dumps({"name": name,
                                                            "version": version}))
    return directory


def scan_in(monkeypatch, *paths):
    monkeypatch.setattr(config, "XO_PLUGIN_LOOKUP_PATHS", [str(p) for p in paths])
    return xoa.scan_plugins()


# --------------------------------------------------------------------------------------
# the scan: what counts as installed
# --------------------------------------------------------------------------------------

def test_scan_finds_every_plugin_dir(monkeypatch, tmp_path):
    for name in STOCK:
        plant(tmp_path, name)
    plugins, errors = scan_in(monkeypatch, tmp_path)
    assert errors == []
    assert sorted(p["name"] for p in plugins) == ["audit", "netbox", "transport-email"]


def test_scan_ignores_everything_not_prefixed(monkeypatch, tmp_path):
    """The prefix is the whole definition of a plugin, so nothing else may creep in."""
    plant(tmp_path, "xo-server-audit")
    plant(tmp_path, "xo-server")            # xo-server itself is not a plugin of itself
    plant(tmp_path, "xo-web")
    plant(tmp_path, "xoa-updater")
    plugins, _errors = scan_in(monkeypatch, tmp_path)
    assert [p["name"] for p in plugins] == ["audit"]


def test_scan_finds_scoped_plugins(monkeypatch, tmp_path):
    """registerPlugins() looks in <path>/@xen-orchestra for `server-*` as well."""
    plant(tmp_path, "server-sneaky", scope="@xen-orchestra")
    plugins, _errors = scan_in(monkeypatch, tmp_path)
    assert [p["name"] for p in plugins] == ["sneaky"]


def test_scan_reads_the_version(monkeypatch, tmp_path):
    plant(tmp_path, "xo-server-thing", version="2.4.1")
    plugins, _errors = scan_in(monkeypatch, tmp_path)
    assert plugins[0]["version"] == "2.4.1"


def test_a_broken_package_json_does_not_hide_the_plugin(monkeypatch, tmp_path):
    """The finding may never depend on the plugin's own metadata parsing."""
    directory = plant(tmp_path, "xo-server-thing", version=None)
    (directory / "package.json").write_text("{ this is not json")
    plugins, _errors = scan_in(monkeypatch, tmp_path)
    assert [p["name"] for p in plugins] == ["thing"]
    assert plugins[0]["version"] == ""


def test_a_symlinked_plugin_is_found_and_its_target_named(monkeypatch, tmp_path):
    """npm link, and the from-source install the XO docs describe, both land here."""
    elsewhere = tmp_path / "elsewhere" / "xo-server-homegrown"
    elsewhere.mkdir(parents=True)
    (elsewhere / "package.json").write_text(json.dumps({"version": "0.1.0"}))
    modules = tmp_path / "modules"
    modules.mkdir()
    try:
        os.symlink(str(elsewhere), str(modules / "xo-server-homegrown"))
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available to this user")
    plugins, _errors = scan_in(monkeypatch, modules)
    assert plugins[0]["name"] == "homegrown"
    assert plugins[0]["version"] == "0.1.0"
    assert plugins[0]["link"].endswith("xo-server-homegrown")


def test_first_lookup_path_wins(monkeypatch, tmp_path):
    """xo-server keeps the first path that has a name; a second copy is not a second
    plugin, and counting it twice would make the totals on the line wrong."""
    first, second = tmp_path / "a", tmp_path / "b"
    plant(first, "xo-server-audit", version="1.0.0")
    plant(second, "xo-server-audit", version="9.9.9")
    plugins, _errors = scan_in(monkeypatch, first, second)
    assert len(plugins) == 1
    assert plugins[0]["version"] == "1.0.0"


def test_a_missing_lookup_path_is_an_answer_not_an_error(monkeypatch, tmp_path):
    """Two of the three shipped lookup paths do not exist on a stock appliance."""
    plant(tmp_path, "xo-server-audit")
    plugins, errors = scan_in(monkeypatch, tmp_path, tmp_path / "nope")
    assert errors == []
    assert [p["name"] for p in plugins] == ["audit"]


def test_an_unlistable_lookup_path_is_an_error(monkeypatch, tmp_path):
    """Unreadable is not empty - reporting it as 'nothing installed' is the silent green
    this tool exists to prevent."""
    def boom(path):
        raise OSError(13, "Permission denied")
    monkeypatch.setattr(os, "listdir", boom)
    _plugins, errors = scan_in(monkeypatch, tmp_path)
    assert errors and "Permission denied" in errors[0]


# --------------------------------------------------------------------------------------
# the manifest: the half of the golden list that keeps itself current
# --------------------------------------------------------------------------------------

MANIFEST = """\
 {
  channel: 'stable',
  updater: { 'xoa-updater': '0.50.12' },
  engine: { node: '22.22.2' },
  npm: {
    'xen-orchestra': '6.7.1',
    'xo-cli-premium': '0.32.3',
    'xo-server-audit-premium': '0.15.1',
    'xo-server-telemetry': '0.7.0',
    'xo-server-brand-new': '1.0.0',
    'xo-server': '5.207.2',
    'xo-web-premium': '5.201.0'
  }
}
"""


def test_manifest_names_strip_both_affixes():
    names = parsers.manifest_plugin_names(MANIFEST)
    assert "audit" in names            # xo-server-audit-premium -> audit
    assert "telemetry" in names        # no -premium suffix on this one
    assert "brand-new" in names


def test_manifest_names_exclude_xo_server_itself():
    """`xo-server` is in the same map and is not a plugin; a stray "" in the golden set
    would be harmless today and a trap the moment a name went empty."""
    names = parsers.manifest_plugin_names(MANIFEST)
    assert "" not in names
    assert not any(n.startswith("xo-") for n in names)


def test_manifest_names_ignore_everything_else():
    names = parsers.manifest_plugin_names(MANIFEST)
    assert "xoa-updater" not in names and "cli" not in names and "web" not in names


def test_no_manifest_is_an_empty_set_not_a_crash():
    """The updater being down leaves the built-in list as the whole golden list."""
    assert parsers.manifest_plugin_names("") == set()
    assert parsers.manifest_plugin_names(None) == set()


# --------------------------------------------------------------------------------------
# the line
# --------------------------------------------------------------------------------------

def line_for(monkeypatch, tmp_path, manifest=(), autoload=None, autoload_known=False):
    plugins, errors = scan_in(monkeypatch, tmp_path)
    return xoa._plugins_line({"plugins": plugins,
                              "plugin_errors": errors,
                              "manifest_plugins": set(manifest),
                              "plugin_autoload": autoload or {},
                              "plugin_autoload_known": autoload_known})


def test_a_stock_appliance_is_green(monkeypatch, tmp_path):
    for name in STOCK:
        plant(tmp_path, name)
    line = line_for(monkeypatch, tmp_path)
    assert not line.flags
    assert "3 installed" in line.render()


def test_a_third_party_plugin_flags(monkeypatch, tmp_path):
    for name in STOCK:
        plant(tmp_path, name)
    plant(tmp_path, "xo-server-tag-automation", version="1.2.0")
    line = line_for(monkeypatch, tmp_path)
    assert line.flags
    assert "1 of 4" in line.render()
    assert "tag-automation" in line.detail_text
    assert "1.2.0" in line.detail_text


def test_the_manifest_rescues_a_plugin_the_built_in_list_never_heard_of(monkeypatch,
                                                                       tmp_path):
    """The built-in list is a fallback, not the answer. A plugin Vates adds after this
    script was written is in the appliance's own manifest, and must not be reported as
    somebody else's."""
    plant(tmp_path, "xo-server-brand-new")
    assert "brand-new" not in config.XOA_STOCK_PLUGINS
    assert line_for(monkeypatch, tmp_path, manifest=["brand-new"]).flags is False


def test_without_a_manifest_the_built_in_list_still_answers(monkeypatch, tmp_path):
    """A wedged or unregistered xoa-updater must not turn every stock plugin into a
    finding - that would be 23 false positives on an appliance whose real problem is the
    updater, which has its own line."""
    for name in STOCK:
        plant(tmp_path, name)
    assert line_for(monkeypatch, tmp_path, manifest=[]).flags is False


def test_an_unreadable_lookup_path_is_unknown_not_green(monkeypatch, tmp_path):
    def boom(path):
        raise OSError(13, "Permission denied")
    monkeypatch.setattr(os, "listdir", boom)
    line = line_for(monkeypatch, tmp_path)
    assert line.status == result.UNKNOWN
    assert line.flags


def test_autoload_is_reported_when_it_was_established(monkeypatch, tmp_path):
    plant(tmp_path, "xo-server-tag-automation")
    line = line_for(monkeypatch, tmp_path,
                    autoload={"tag-automation": True}, autoload_known=True)
    assert "autoload on" in line.detail_text


def test_a_plugin_xo_has_never_loaded_says_so(monkeypatch, tmp_path):
    """Installed but never loaded has no metadata record at all, which is a different
    thing from loaded-and-switched-off and reads differently."""
    plant(tmp_path, "xo-server-tag-automation")
    line = line_for(monkeypatch, tmp_path, autoload={"audit": True}, autoload_known=True)
    assert "never loaded by XO" in line.detail_text


def test_unreadable_autoload_does_not_imply_inert(monkeypatch, tmp_path):
    """redis declining is not evidence the plugin is switched off, and the block may not
    read as though it were."""
    plant(tmp_path, "xo-server-tag-automation")
    line = line_for(monkeypatch, tmp_path, autoload={}, autoload_known=False)
    assert "autoload unknown" in line.detail_text
    assert "autoload off" not in line.detail_text
    assert line.flags


def test_autoload_never_produces_a_finding_on_its_own(monkeypatch, tmp_path):
    """`xo:plugin-metadata:cloud` outlives the plugin by years. A stale record for
    something not installed is not an installed plugin."""
    plant(tmp_path, "xo-server-audit")
    line = line_for(monkeypatch, tmp_path,
                    autoload={"cloud": True, "tag-automation": True}, autoload_known=True)
    assert not line.flags
