# Screenshots

Real evidence for the README showcase.

| File | What it shows |
|------|---------------|
| `green-pipeline.png` | A passing `detections-ci` run on `main`: lint, test, and convert, then the deploy job. |
| `blocked-pr.png` | The Checks tab of [PR #1](https://github.com/manlikefelo/detection-as-code/pull/1), with the required `lint -> test -> convert` check failed. It was captured logged out, where GitHub doesn't show the merge box; open the PR signed in to see the block itself. |
| `one-test-pair.png` | The Kerberoasting lines of the `pytest -v` output from the CI run on `main`, rendered as an image. |

See [`examples/broken-rule-demo/`](../examples/broken-rule-demo/) for the steps that
produce the blocked state.
