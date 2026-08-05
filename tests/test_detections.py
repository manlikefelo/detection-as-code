"""
test_detections.py - the CI quality gate for detection content.

For EVERY rule under rules/ this suite asserts:
  1. the rule has a paired samples file with at least one true positive
     (a rule with no tests fails CI);
  2. every true-positive sample makes the rule FIRE (no false negatives);
  3. every benign sample does NOT make the rule fire (no false positives).

Sample shapes supported per case:
  event: {...}                      -> a single event
  events: [ {...}, {...} ]          -> an explicit list of events
  events + repeat_each: N           -> repeat the whole list N times (bursts)
  burst: { count: N, event: {...} } -> N copies of one event (correlation bursts)
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from rule_loader import discover_rules, load_yaml, samples_path_for  # noqa: E402
from sigma_matcher import load_rule, rule_fires  # noqa: E402

RULES = discover_rules()


def _events_from_case(case: dict) -> list[dict]:
    """Normalise any supported sample shape into a flat list of event dicts."""
    if "burst" in case:
        b = case["burst"]
        return [dict(b["event"]) for _ in range(int(b["count"]))]
    if "events" in case:
        base = [dict(e) for e in case["events"]]
        repeat = int(case.get("repeat_each", 1))
        out: list[dict] = []
        for _ in range(repeat):
            out.extend(dict(e) for e in base)
        return out
    if "event" in case:
        return [dict(case["event"])]
    raise ValueError(f"Sample case has no event/events/burst key: {case!r}")


def _load(rule_path: Path):
    rule = load_rule(load_yaml(rule_path))
    samples_path = samples_path_for(rule_path)
    samples = load_yaml(samples_path) if samples_path.exists() else None
    return rule, samples_path, samples


@pytest.mark.parametrize("rule_path", RULES, ids=[p.stem for p in RULES])
def test_rule_has_samples_with_true_positives(rule_path: Path):
    """A rule with no test file, or no true positives, fails CI."""
    _, samples_path, samples = _load(rule_path)
    assert samples is not None, f"Rule {rule_path.name} has NO samples file at {samples_path}"
    tps = samples.get("true_positives") or []
    assert len(tps) >= 1, f"Rule {rule_path.name} has no true-positive samples"


@pytest.mark.parametrize("rule_path", RULES, ids=[p.stem for p in RULES])
def test_true_positives_fire(rule_path: Path):
    """Every true-positive sample must make the rule fire."""
    rule, samples_path, samples = _load(rule_path)
    assert samples is not None, f"Rule {rule_path.name} has NO samples file at {samples_path}"
    for case in samples.get("true_positives", []):
        events = _events_from_case(case)
        assert rule_fires(rule, events), (
            f"[{rule.title}] expected to FIRE on TP '{case.get('name')}' but did not"
        )


@pytest.mark.parametrize("rule_path", RULES, ids=[p.stem for p in RULES])
def test_benign_does_not_fire(rule_path: Path):
    """No benign sample may make the rule fire."""
    rule, samples_path, samples = _load(rule_path)
    assert samples is not None, f"Rule {rule_path.name} has NO samples file at {samples_path}"
    for case in samples.get("benign", []):
        events = _events_from_case(case)
        assert not rule_fires(rule, events), (
            f"[{rule.title}] false positive on benign '{case.get('name')}'"
        )
