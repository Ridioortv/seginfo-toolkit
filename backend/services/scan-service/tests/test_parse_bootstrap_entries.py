"""parse_bootstrap_entries: lectura tolerante de BOOTSTRAP_AGENTS."""
import json

from app.services import parse_bootstrap_entries


def test_flat_list():
    raw = json.dumps([{"name": "A", "key": "ka"}, {"name": "B", "key": "kb"}])
    assert [e["name"] for e in parse_bootstrap_entries(raw)] == ["A", "B"]


def test_nested_lists_are_flattened():
    raw = json.dumps([[{"name": "A", "key": "ka"}, {"name": "B", "key": "kb"}], {"name": "C", "key": "kc"}])
    assert [e["name"] for e in parse_bootstrap_entries(raw)] == ["A", "B", "C"]


def test_entries_without_name_or_key_are_skipped():
    raw = json.dumps([{"name": "A"}, {"key": "k"}, {"name": "B", "key": "kb"}])
    assert [e["name"] for e in parse_bootstrap_entries(raw)] == ["B"]


def test_empty_or_invalid_returns_none():
    assert parse_bootstrap_entries("") is None
    assert parse_bootstrap_entries("{nope") is None
