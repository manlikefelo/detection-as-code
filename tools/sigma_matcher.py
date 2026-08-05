"""
sigma_matcher.py - a small, dependency-light Sigma detection evaluator.

Why this exists
---------------
The CI test harness needs to answer one question for every rule: "given this log
event, does the rule's detection logic fire?" - and it needs to answer it fast,
offline, with no live SIEM. pySigma converts rules into *backend queries*; it does
not evaluate them against sample events. So this module implements just enough of
the Sigma condition/field-modifier semantics to run a rule against a Python dict
that represents one (or a burst of) log event(s).

It deliberately supports only the subset of Sigma my rules actually use:
  - selection maps: field -> value | list-of-values (OR within a field)
  - field modifiers: |contains, |endswith, |startswith, |re
  - conditions: "selection", "sel1 and not 1 of filter_*", "a or b", etc.
  - count() correlation: "selection | count() by <field> > N" over a timeframe

If a rule uses a construct this matcher does not understand, it raises
UnsupportedSigmaError rather than silently passing - a rule the harness cannot
evaluate must not be treated as tested.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


class UnsupportedSigmaError(Exception):
    """Raised when a rule uses Sigma syntax this matcher does not implement."""


# --------------------------------------------------------------------------- #
# Field-modifier comparison of a single event field against a single criterion
# --------------------------------------------------------------------------- #
def _compare(event_value: Any, modifier: str | None, expected: Any) -> bool:
    """Compare one event field value against one expected value + modifier."""
    if event_value is None:
        return False
    ev = str(event_value)
    exp = str(expected)

    if modifier is None:
        return ev == exp
    if modifier == "contains":
        return exp in ev
    if modifier == "endswith":
        return ev.endswith(exp)
    if modifier == "startswith":
        return ev.startswith(exp)
    if modifier == "re":
        return re.search(exp, ev) is not None
    raise UnsupportedSigmaError(f"Unsupported field modifier: |{modifier}")


def _field_matches(event: dict, key: str, criterion: Any) -> bool:
    """
    Evaluate one 'field[|modifier]: value|list' entry of a selection.
    A list of values is an OR: any element matching is a match.
    """
    if "|" in key:
        field_name, modifier = key.split("|", 1)
    else:
        field_name, modifier = key, None

    event_value = event.get(field_name)
    expected_values = criterion if isinstance(criterion, list) else [criterion]
    return any(_compare(event_value, modifier, exp) for exp in expected_values)


def _selection_matches(event: dict, selection: dict) -> bool:
    """A selection map matches only if ALL its field entries match (AND)."""
    return all(_field_matches(event, key, crit) for key, crit in selection.items())


# --------------------------------------------------------------------------- #
# Condition evaluation
# --------------------------------------------------------------------------- #
@dataclass
class Rule:
    title: str
    detection: dict
    correlation: dict | None = field(default=None)

    @property
    def is_correlation(self) -> bool:
        return self.correlation is not None


def _resolve_identifier(event: dict, detection: dict, name: str) -> bool:
    """Resolve a single selection/filter identifier (or a 'x of filter_*' form)."""
    if name not in detection:
        raise UnsupportedSigmaError(f"Condition references unknown identifier: {name}")
    return _selection_matches(event, detection[name])


def _eval_1_of(event: dict, detection: dict, pattern: str) -> bool:
    """Evaluate '1 of filter_*' -> True if ANY identifier matching the glob matches."""
    prefix = pattern.rstrip("*")
    candidates = [k for k in detection if k.startswith(prefix) and k != "condition"]
    if not candidates:
        raise UnsupportedSigmaError(f"No identifiers match pattern: {pattern}")
    return any(_selection_matches(event, detection[c]) for c in candidates)


def _eval_condition(event: dict, detection: dict) -> bool:
    """
    Evaluate the (small) set of condition grammars my rules use.
    Supported shapes:
      - "selection"
      - "a and b", "a or b"
      - "selection and not 1 of filter_*"
      - "sqli or xss"
    """
    condition = detection["condition"].strip()

    # Shape: "<sel> and not 1 of <glob>"
    m = re.fullmatch(r"(\w+)\s+and\s+not\s+1\s+of\s+(\w+\*)", condition)
    if m:
        sel, glob = m.group(1), m.group(2)
        return _resolve_identifier(event, detection, sel) and not _eval_1_of(event, detection, glob)

    # Shape: "a or b"  (any number of OR terms)
    if " or " in condition and " and " not in condition:
        terms = [t.strip() for t in condition.split(" or ")]
        return any(_resolve_identifier(event, detection, t) for t in terms)

    # Shape: "a and b" (any number of AND terms, no not/of)
    if " and " in condition and "not" not in condition and " of " not in condition:
        terms = [t.strip() for t in condition.split(" and ")]
        return all(_resolve_identifier(event, detection, t) for t in terms)

    # Shape: bare identifier "selection"
    if re.fullmatch(r"\w+", condition):
        return _resolve_identifier(event, detection, condition)

    raise UnsupportedSigmaError(f"Unsupported condition grammar: {condition!r}")


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def load_rule(rule_dict: dict) -> Rule:
    """Turn a parsed Sigma YAML dict into a Rule, detecting count() correlation."""
    detection = rule_dict["detection"]
    condition = detection.get("condition", "")
    correlation = None
    m = re.search(r"count\(\)\s+by\s+(\w+)\s*>\s*(\d+)", str(condition))
    if m:
        correlation = {
            "group_by": m.group(1),
            "threshold": int(m.group(2)),
            "base": "selection",  # the events counted are those matching 'selection'
        }
    return Rule(title=rule_dict.get("title", "untitled"), detection=detection, correlation=correlation)


def rule_fires(rule: Rule, events: list[dict]) -> bool:
    """
    Does this rule fire against the supplied event(s)?

    - Single-event rules: fire if ANY event in the list matches the selection logic.
      (A test usually supplies exactly one event.)
    - Correlation (count()) rules: fire if the number of events matching the base
      selection, grouped by the group_by field, exceeds the threshold for any group.
    """
    if rule.is_correlation:
        base_sel = rule.detection[rule.correlation["base"]]
        group_by = rule.correlation["group_by"]
        threshold = rule.correlation["threshold"]
        counts: dict[str, int] = {}
        for ev in events:
            if _selection_matches(ev, base_sel):
                key = str(ev.get(group_by))
                counts[key] = counts.get(key, 0) + 1
        return any(c > threshold for c in counts.values())

    return any(_eval_condition(ev, rule.detection) for ev in events)
