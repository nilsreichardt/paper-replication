# Replication package

This package contains pipeline code, agent prompt templates and configuration,
privacy-reduced research data, artificial A–F workflow examples, and a label-gate
mitigation.

## Reproduce the released analyses without credentials

From the repository root:

```sh
uv run python replication/scripts/reproduce.py --output replication/results/summary.json
```

The analysis uses only the Python standard library and the released data. It
checks aggregate totals, outcome denominators, the credential-evidence union,
and every released CSV against its source aggregate. No target is contacted.
For an entirely dependency-free run, use an installed Python 3.12 interpreter.

```sh
uv sync --locked --group dev
uv run pytest -q
uv run python replication/scripts/run_synthetic.py
```

The last command executes harmless marker programs through all six synthetic
pathways. It needs Node/npm and make in addition to the Python test environment.
It does not evaluate agent effectiveness or perform live exploit verification.

## Components

- `../src/`: deterministic controller, source collection, AI-assisted analysis,
  owned-fork verification, and agent prompts.
- `vendor/gato-x/`: the fork of the static scanner, exported without Git history.
- `config/study.json`: separates evidence from recollection and reproduction pins.
- `config/package.json`: pins Gemini CLI to 0.34.0 for reproduction.
- `synthetic/`: new, artificial A–F projects with harmless marker payloads.
- `data/`: independently shuffled, unlinked per-repository projections and
  complete marginal aggregates. See `DATA_DICTIONARY.md`.
- `mitigation/`: vendored label-gate action and its unit tests.
- `scripts/export_data.py`: author-side transformation of private inputs. Reviewers
  do not need or receive those inputs to recompute the released summaries.

## Repeating the agent experiment

The released data captures the study at collection time, and the analysis scripts
recompute the reported marginal results from this fixed snapshot. A fresh run
against GitHub cannot be expected to reproduce exactly the same repository
population or counts: repositories may since have been made private, deleted,
renamed, or patched, and workflows and dependencies may have changed. Model
nondeterminism and changes to model availability can also affect verification
outcomes.

The original repository identities, commit hashes, generated exploits and raw
transcripts are withheld. A rerun on the historical population is therefore not
provided. The original experiment also depends on GitHub, external tools and a
non-deterministic preview model. An offline synthetic marker run is not a full
agent experiment.

See `synthetic/README.md` and `OWNED_DEMO.md` for owned-repository demonstrations. All six fixtures
must be used only in isolated, reviewer-owned repositories with synthetic data.
No large-scale scanning or live attack command is part of the quick start.

## Review snapshot

This is the prepared anonymous source export. Historical raw inputs and original
Git history are withheld. Pipeline code uses the root LICENSE; vendored components
preserve their individual licenses. Released data and new examples use
replication/LICENSE.
