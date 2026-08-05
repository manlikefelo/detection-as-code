"""
rule_loader.py - discover rules and their paired test-sample files.

Convention (enforced by CI):
  rules/<tactic>/<name>.yml     ->  the Sigma rule
  tests/<name>.yml              ->  its samples: {true_positives: [...], benign: [...]}

A rule whose test file is missing, or whose test file has zero true_positives,
FAILS - "a rule with no tests fails CI" is the whole point of the harness.
"""
from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
TESTS_DIR = REPO_ROOT / "tests"


def discover_rules() -> list[Path]:
    """Every .yml under rules/, sorted for stable test ordering."""
    return sorted(RULES_DIR.rglob("*.yml"))


def samples_path_for(rule_path: Path) -> Path:
    """The expected samples file for a given rule (matched by filename stem)."""
    return TESTS_DIR / f"{rule_path.stem}.yml"


def load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))
