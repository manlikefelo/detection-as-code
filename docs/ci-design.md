# CI design — rules as code

This document explains the pipeline stages and the philosophy behind treating
detection content the way a software team treats source code.

## The "rules as code" philosophy

A detection rule is an asset with the same failure modes as any other code: it can
be malformed, it can stop matching what it's supposed to, and it can start matching
things it shouldn't (false positives). Yet detections are usually authored ad hoc —
pasted into a SIEM console, never tested, never reviewed, with no history of who
changed what or why. When an alert misfires at 3 a.m., nobody can tell whether the
rule ever worked.

Treating rules as code fixes that with four properties borrowed straight from
software engineering:

1. **Version control as an audit trail.** Every rule change is a commit: author,
   timestamp, diff, and reason. `git blame` on a rule answers "why is this here?"
2. **Peer review via pull request.** A rule change is proposed, not applied. A
   teammate reviews the logic and the samples before it reaches `main`.
3. **Test coverage.** Each rule ships with sample events proving it fires on the
   real thing and stays quiet on look-alikes. A rule with no tests is not trusted —
   the pipeline rejects it.
4. **A quality gate in CI.** The three checks below run automatically on every PR.
   A red check blocks the merge. Good detections get in; broken ones don't.

## The three stages

### 1 · Lint — `tools/lint_rules.py`
Two layers:
- **Spec compliance:** every rule is parsed with `pySigma`'s `SigmaCollection`. If
  pySigma can't parse it, it isn't a valid Sigma rule against the current spec, and
  the stage fails.
- **House rules:** required metadata (`title`, `id`, `status`, `level`, `logsource`,
  `detection`), a valid severity `level`, at least one ATT&CK technique tag, and a
  paired samples file. These keep the content consistently reviewable.

### 2 · Test — `pytest` + `tools/sigma_matcher.py`
For every rule the suite asserts three things:
- the rule has a samples file with **at least one true positive** (no tests ⇒ fail);
- **every** true-positive sample makes the rule fire (no false negatives);
- **no** benign sample makes the rule fire (no false positives).

Tests run against `sigma_matcher.py`, a small offline evaluator of Sigma detection
logic (field modifiers `contains`/`endswith`/`startswith`/`re`, list-OR, the
`… and not 1 of filter_*` idiom, and `count()` correlation). This means the gate
needs **no live SIEM** — it runs in seconds on a stock GitHub runner. If a rule uses
Sigma syntax the matcher doesn't implement, the matcher raises rather than passing
silently, so an un-evaluatable rule is never mistaken for a tested one.

### 3 · Convert — `tools/convert_rules.py`
Compiles each rule to two targets, written to `build/converted/`:
- **Lucene** (`<name>.lucene`) via pySigma's maintained Elasticsearch backend — a
  strong second signal of spec conformance.
- **Wazuh** (`wazuh_local_rules.xml`) — my home lab's SIEM. There is no maintained
  pySigma Wazuh backend, so this is a deliberately simple, documented mapping of each
  rule's selection fields to a Wazuh `<rule>`, mirroring the hand-written rules
  already deployed in my detection-engineering repo. It's an approximation, not a
  1:1 compiler: windowed `count()` correlations are emitted with a `TODO` for a human
  to wire to a Wazuh `<frequency>` rule, because field matching alone would over-fire.

## From artifact to live SIEM

On merge to `main`, the **deploy** job re-runs the convert step and publishes
`wazuh_local_rules.xml` as a build artifact. That artifact is the clean handoff point
to a live environment. In production this same file would be pushed to the Wazuh
manager — for example:

1. CI uploads `wazuh_local_rules.xml` (done here).
2. A deploy step copies it to `/var/ossec/etc/rules/local_rules.xml` on the manager
   (over SSH, or via Ansible / the Wazuh API), keyed on a secret held in the CI
   environment, never in git.
3. `wazuh-control restart` reloads the ruleset.
4. A post-deploy smoke test replays one known-malicious event and asserts the alert
   fires.

This repo stops at step 1 on purpose: the lab SIEM isn't reachable from a public CI
runner, and publishing the artifact keeps the pipeline fully free and reproducible
while documenting exactly how the last mile would work.

## Why a QA background matters here

Sample-based testing, boundary cases (the BloodHound rule is tested at *exactly* the
threshold of 15 as well as over it), red/green gates, and "no code without a test" are
everyday test-automation discipline. Applying them to detections is what turns
"I wrote some rules" into "I ship detection content a team can depend on."
