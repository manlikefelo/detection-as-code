# Contributing a detection

Adding a detection is deliberately the same shape as adding a feature to a codebase:
write it, test it, open a PR, let CI gate it. A rule doesn't reach `main` until the
pipeline is green.

## The workflow

### 1. Write the rule
Create a Sigma rule under the folder for its ATT&CK **tactic**:

```
rules/<tactic>/<short_name>.yml
```

e.g. `rules/lateral-movement/psexec_service_install.yml`. It must have `title`, `id`
(a UUID), `status`, `level`, `logsource`, `detection`, and at least one ATT&CK
technique tag (`attack.tXXXX`). The lint stage enforces all of this.

### 2. Add its test samples
Create `tests/<short_name>.yml`, **the filename stem must match the rule's**, with
true-positive events (must alert) and benign events (must not):

```yaml
true_positives:
  - name: what makes this malicious
    event:
      EventID: 7045
      ServiceName: PSEXESVC
benign:
  - name: a legitimate look-alike that must NOT fire
    event:
      EventID: 7045
      ServiceName: MyLegitApp
```

**Aim your benign samples at the rule's filters.** The best FP samples are the events
your rule *almost* fires on: a machine account, `krbtgt`, a value one character off.
That's where detections actually break.

Sample shapes the harness understands:

| Shape | Use for |
|-------|---------|
| `event: {…}` | a single event |
| `events: [ {…}, … ]` | an explicit list of events |
| `events: […]` + `repeat_each: N` | repeat the list N times |
| `burst: { count: N, event: {…} }` | N copies of one event (for `count()` correlation rules) |

### 3. Run the gates locally
```bash
pip install -r requirements.txt
python tools/lint_rules.py
python -m pytest -v
python tools/convert_rules.py
```

### 4. Open a pull request
CI runs **lint → test → convert**. If any stage is red: a malformed rule, a
true positive that doesn't fire, a benign event that does, or a rule with no
samples: **the PR is blocked**. Fix it and push again; merge when green.

### 5. Merge
On merge to `main`, the deploy job compiles the ruleset and publishes it as an
artifact (the handoff to the live SIEM, see [docs/ci-design.md](docs/ci-design.md)).

## Checklist before you open the PR
- [ ] Rule is under the correct `rules/<tactic>/` folder
- [ ] Rule has a UUID `id`, a `level`, and an `attack.tXXXX` tag
- [ ] `tests/<same-stem>.yml` exists with ≥1 true positive
- [ ] At least one benign sample targets the rule's filters
- [ ] `pytest` and `lint_rules.py` pass locally
- [ ] No secrets, real credentials, or real hostnames in the rule or samples
