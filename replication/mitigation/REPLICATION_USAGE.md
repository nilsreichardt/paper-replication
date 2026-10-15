# Local label-gate action

This is a source snapshot of the mitigation described in the paper. Its real-world
effectiveness was not evaluated in the study. Tests cover its label handling.

From this directory, with Node 24 and npm:

```sh
npm ci --ignore-scripts
npm test -- --runInBand
```

For an owned demonstration, keep the action under a trusted base-branch path
such as `replication/mitigation`. Install its locked dependencies before using
the local action. Do not load the guard from the untrusted pull request head.

```yaml
on:
  pull_request_target:
    types: [opened, synchronize, reopened, labeled]
permissions:
  contents: read
  issues: write
jobs:
  guarded:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.base.sha }}
      - uses: actions/setup-node@v4
        with:
          node-version: '24'
      - run: npm ci --ignore-scripts --omit=dev --prefix replication/mitigation
      - uses: ./replication/mitigation
        with:
          label: safe to test
          require-reapproval: 'true'
      # Add an owned, harmless demonstration step here.
```

The action fails for a fork PR without the approval label; by default it removes
the label after approval to require reapproval. Do not claim this example is a
complete defense against every race or workflow configuration; it is the
unevaluated mitigation artifact accompanying the paper.
