# Repo guide

For anyone seeing this repo for the first time. The point of
this repo is a single idea: **detection rules gated like production code.** Here's the
fastest way to see that it's real.

### 1 · The CI run first (60s): `.github/workflows/detections-ci.yml`
Start here. Open the **Actions** tab and look at a `detections-ci` run:
three stages, **lint → test → convert**, then a **deploy** job on `main`. The
pipeline definition is [`.github/workflows/detections-ci.yml`](../.github/workflows/detections-ci.yml).
Every pull request that touches a rule runs this. A red stage blocks the merge.

**See it block a bad rule:** [`examples/broken-rule-demo/`](../examples/broken-rule-demo/)
has an intentionally broken rule and the exact steps to watch CI reject it, then pass
once it's fixed. The blocked-PR screenshot is in [`screenshots/`](../screenshots/).

### 2 · One rule's test pair (60s): `tests/kerberoasting_rc4_tgs.yml`
Open [`tests/kerberoasting_rc4_tgs.yml`](../tests/kerberoasting_rc4_tgs.yml) next to
the rule [`rules/credential-access/kerberoasting_rc4_tgs.yml`](../rules/credential-access/kerberoasting_rc4_tgs.yml).
Note the benign samples: an RC4 ticket for a **machine account** (`WS01$`) and one for
**`krbtgt`**: both must *not* fire. That's the difference between a real detection and
a naive one, and CI proves the rule gets it right on every push.

### 3 · The deploy stage (30s): `docs/ci-design.md`
Read the *"From artifact to live SIEM"* section of
[`docs/ci-design.md`](ci-design.md). It shows where the pipeline hands the compiled
Wazuh ruleset (`build/converted/wazuh_local_rules.xml`) off to a live SIEM, and
explains where this free/reproducible version stops and why.

---
**The takeaway:** this is QA/test-automation discipline (version control, unit tests,
red/green gates, "no code without a test") applied to detection content. Rules here
are treated exactly like software a team depends on.
