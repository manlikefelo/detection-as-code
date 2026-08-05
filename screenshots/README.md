# Screenshots

Real evidence for the README showcase. Capture these from the live GitHub Actions
runs and your terminal (full-size windows).

| File | What to capture |
|------|-----------------|
| `green-pipeline.png` | A passing `detections-ci` run — the three green stages (lint → test → convert) plus the deploy job on `main`. |
| `blocked-pr.png` | A pull request with the broken rule from `examples/broken-rule-demo/` — the red `detections-ci` check and the "merge blocked" banner. |
| `one-test-pair.png` | Terminal: `pytest -v` output showing the Kerberoasting rule's TP firing and benign (machine-account / krbtgt) samples staying quiet. |

See [`examples/broken-rule-demo/`](../examples/broken-rule-demo/) for the exact steps
to produce the blocked-PR state.
