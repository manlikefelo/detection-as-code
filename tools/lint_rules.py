#!/usr/bin/env python3
"""
lint_rules.py - the CI lint stage. Fails on any malformed or non-conformant rule.

Two layers of validation:
  1. SPEC: parse every rule with pySigma's SigmaCollection. If pySigma cannot parse
     it, it is not a valid Sigma rule against the current spec -> fail.
  2. HOUSE RULES: enforce repo conventions that keep the content reviewable:
       - required metadata: title, id, status, level, logsource, detection
       - at least one ATT&CK technique tag (attack.tXXXX...)
       - a paired samples file must exist (ties into "no tests => fail CI")

Exit code 0 = clean, 1 = one or more problems (printed).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml  # noqa: E402
from rule_loader import discover_rules, samples_path_for  # noqa: E402

try:
    from sigma.collection import SigmaCollection
except ImportError:  # pragma: no cover
    print("pysigma not installed; run: pip install -r requirements.txt")
    sys.exit(2)

REQUIRED_KEYS = ("title", "id", "status", "level", "logsource", "detection")
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}


def lint_rule(path: Path) -> list[str]:
    """Return a list of human-readable problems for one rule (empty = clean)."""
    problems: list[str] = []
    raw = path.read_text(encoding="utf-8")

    # Layer 1: spec compliance via pySigma
    try:
        SigmaCollection.from_yaml(raw)
    except Exception as exc:  # pysigma raises various SigmaError subclasses
        problems.append(f"pySigma spec error: {exc}")
        return problems  # if it won't parse, house-rule checks are moot

    doc = yaml.safe_load(raw)

    # Layer 2: house rules
    for key in REQUIRED_KEYS:
        if key not in doc:
            problems.append(f"missing required key: '{key}'")

    level = doc.get("level")
    if level is not None and level not in VALID_LEVELS:
        problems.append(f"invalid level '{level}' (expected one of {sorted(VALID_LEVELS)})")

    tags = doc.get("tags", []) or []
    if not any(str(t).startswith("attack.t") for t in tags):
        problems.append("no ATT&CK technique tag (expected an 'attack.tXXXX' tag)")

    if not samples_path_for(path).exists():
        problems.append(f"no samples file: expected tests/{path.stem}.yml")

    return problems


def main() -> int:
    rules = discover_rules()
    if not rules:
        print("No rules found under rules/ - nothing to lint.")
        return 1

    total_problems = 0
    for path in rules:
        rel = path.relative_to(path.parents[2]) if len(path.parents) >= 3 else path
        problems = lint_rule(path)
        if problems:
            total_problems += len(problems)
            print(f"FAIL  {rel}")
            for p in problems:
                print(f"        - {p}")
        else:
            print(f"ok    {rel}")

    print("-" * 60)
    if total_problems:
        print(f"Lint FAILED: {total_problems} problem(s) across {len(rules)} rule(s).")
        return 1
    print(f"Lint passed: {len(rules)} rule(s) conform to spec + house rules.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
