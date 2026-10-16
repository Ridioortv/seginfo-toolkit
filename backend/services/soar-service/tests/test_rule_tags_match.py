"""rule_tags de un playbook filtra a que alertas responde (antes se ignoraba)."""
from app.services import tags_match


def test_playbook_without_tags_matches_everything():
    assert tags_match([], ["attack.t1059"])
    assert tags_match(None, [])


def test_playbook_with_tags_needs_overlap():
    assert tags_match(["brute_force"], ["attack.t1110", "brute_force"])
    assert not tags_match(["brute_force"], ["attack.t1059"])
    assert not tags_match(["brute_force"], [])


def test_case_and_spaces_are_ignored():
    assert tags_match([" Brute_Force "], ["brute_force"])
    assert tags_match(["", "  "], ["x"])
