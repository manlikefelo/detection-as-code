# Demo: watch CI block a broken rule

This reproduces the blocked pull request: a pull request
rejected by the detection pipeline. Two ways a rule fails the gate; both are shown.

The broken rule lives here (in `examples/`, **not** in `rules/`) so it never breaks
`main`. To demo it, copy it into `rules/` on a branch and open a PR.

## Failure A: a benign event that fires (a false positive the test catches)

`broken_kerberoast.yml` is the Kerberoasting rule with the machine-account filter
**removed**. Its logic now fires on a normal machine-account ticket. Paired with the
real test samples (which include a `WS01$` benign event), `pytest` fails:

```
FAILED tests/test_detections.py::test_benign_does_not_fire[broken_kerberoast]
  [Kerberoasting …] false positive on benign 'RC4 TGS but for a machine account'
```

## Failure B: a rule with no test samples

Drop any valid rule into `rules/` without a matching `tests/<stem>.yml` and the gate
fails at:

```
FAILED tests/test_detections.py::test_rule_has_samples_with_true_positives[<name>]
  Rule <name>.yml has NO samples file
```

...and the lint stage also reports `no samples file: expected tests/<name>.yml`.

## Reproduce it

```bash
git checkout -b demo/broken-rule
cp examples/broken-rule-demo/broken_kerberoast.yml rules/credential-access/
cp tests/kerberoasting_rc4_tgs.yml tests/broken_kerberoast.yml   # reuse the same samples
python -m pytest -q          # <-- FAILS: benign machine-account event now fires
# open the PR -> detections-ci goes red -> merge is blocked
# then delete the file, push again -> green -> merge allowed
```

Capture the red check on the PR for `screenshots/blocked-pr.png`, then the green
run after removing the file for `screenshots/green-pipeline.png`.
