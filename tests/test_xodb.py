# -*- coding: utf-8 -*-
"""The util.inspect scanner. Every case here is one that broke the old parsers."""

import xodb


def test_plain_single_quoted():
    text = "{ host: '192.168.1.5', label: 'XEN-MAIN-01', enabled: 'true' }"
    recs = xodb.scan_records(text)
    assert recs == [{"host": "192.168.1.5", "label": "XEN-MAIN-01", "enabled": "true"}]


def test_double_quoted_when_value_has_an_apostrophe():
    # util.inspect switches quote character per value
    text = "{ label: \"Bob's Pool\", host: '10.0.0.1' }"
    recs = xodb.scan_records(text)
    assert recs[0]["label"] == "Bob's Pool"
    assert recs[0]["host"] == "10.0.0.1"


def test_backtick_when_value_has_both_quote_kinds():
    text = "{ label: `it's \"x\"`, host: '10.0.0.2' }"
    recs = xodb.scan_records(text)
    assert recs[0]["label"] == "it's \"x\""


def test_brace_inside_a_value_does_not_split_the_record():
    # the block-regex parser this replaced split here and lost the password
    text = "{ host: '10.0.0.3', password: 'a}b{c', label: 'P' }"
    recs = xodb.scan_records(text)
    assert len(recs) == 1
    assert recs[0]["password"] == "a}b{c"
    assert recs[0]["label"] == "P"


def test_nested_json_in_the_error_field():
    text = ("{ error: { code: 'ECONNREFUSED', data: { a: 1 } }, "
            "host: '10.0.0.4', label: 'P4' }")
    recs = xodb.scan_records(text)
    assert len(recs) == 1
    assert recs[0]["host"] == "10.0.0.4"
    assert recs[0]["label"] == "P4"


def test_bare_values():
    text = "{ host: '10.0.0.5', enabled: true, n: 42, x: null }"
    recs = xodb.scan_records(text)
    assert recs[0]["enabled"] == "true"
    assert recs[0]["n"] == "42"
    assert recs[0]["x"] == "null"


def test_escape_forms():
    cases = {
        r"a\nb": "a\nb",
        r"a\tb": "a\tb",
        r"a\'b": "a'b",
        r"a\\b": "a\\b",
        r"a\x41b": "aAb",
        r"aAb": "aAb",
        r"a\u{1F600}b": u"a\U0001F600b",
    }
    for raw, want in cases.items():
        recs = xodb.scan_records("{ password: '" + raw + "', host: 'h' }")
        assert recs[0]["password"] == want, raw


def test_multiple_records_in_one_stream():
    text = ("{ host: '1.1.1.1', label: 'A' }\n"
            "{ host: '2.2.2.2', label: 'B' }\n")
    recs = xodb.scan_records(text)
    assert [r["host"] for r in recs] == ["1.1.1.1", "2.2.2.2"]


def test_sort_is_numeric_and_case_insensitive():
    names = ["pool 10", "Pool 2", "POOL 1", "alpha"]
    assert sorted(names, key=xodb._sort_key) == ["alpha", "POOL 1", "Pool 2", "pool 10"]


def test_sort_puts_digits_before_letters():
    # ICU root collation, which is what node's localeCompare uses. This decides which
    # pool a no-args non-interactive run picks, so it is not cosmetic.
    names = ["XEN-PRIMARY", "1st Avenue", "XEN-SECONDARY"]
    assert sorted(names, key=xodb._sort_key) == ["1st Avenue", "XEN-PRIMARY", "XEN-SECONDARY"]


def test_clean_collapses_whitespace():
    assert xodb.clean("  a \t b\nc ") == "a b c"
    assert xodb.clean(None) == ""
