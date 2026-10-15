# Optional demonstration on reviewer-owned repositories

The offline quick start reproduces statistics and tests execution pathways.
The full experiment additionally needs GitHub, two separate owned accounts,
model access, and two services reachable from GitHub-hosted runners. The commands
below are templates for a small, explicitly owned artificial fixture, not a
re-scan of the historical study population. No live run was performed as part
of package preparation.

## Prepare one artificial repository

Copy the contents of one directory under `synthetic/` into a new isolated
repository you own. Use only synthetic values. Enable Actions and allow the
owned fork workflow demonstration. Do not use a production repository.

Install the pinned static scanner from the repository root:

```sh
uv sync --locked --directory replication/vendor/gato-x --extra test
uv run --directory replication/vendor/gato-x gato-x e \
  --repository REVIEWER_OWNED_ACCOUNT/ARTIFICIAL_FIXTURE \
  --skip-runners --output-json /tmp/owned-fixture-enumeration.json
```

The scanner reads `GH_TOKEN`. Its local help confirms these flags. A specific
owned fixture commit can be selected with `--commit SHA`. The generic scanner
may emit other risk types as well; the pipeline selects the relevant
`pull_request_target` finding. Confirm the emitted path and sink before running
the agent; these new fixtures have only been validated with local marker tests,
not a live GitHub/agent experiment.

## Configure the agent runtime and collector

```sh
uv sync --locked --group dev
npm ci --ignore-scripts --prefix replication/config
export PATH="$PWD/replication/config/node_modules/.bin:$PATH"
gemini --version
```

The reproduction pin is Gemini CLI 0.34.0. Authenticate it with an appropriate
account. Historical billing settings are not established; do not treat the
source's OAuth default as a historical measurement.

Deploy the included collector with its locked dependencies and a reviewer-owned
database according to `collector/README.md`. Serve `helper/memdump.py` at a second
reviewer-owned URL. Set these environment variables before using the pipeline:

```sh
export PWNHUNTER_HOOKBIN_URL="https://YOUR-COLLECTOR-HOST"
export PWNHUNTER_MEMDUMP_URL="https://YOUR-HELPER-HOST/memdump.py"
```

The collector accepts a runner's PUT at `/$GITHUB_RUN_ID`, and the controller
retrieves the corresponding evidence through `/api/$GITHUB_RUN_ID`. A loopback
URL works only when all participants share that network context; it is not
reachable from an ordinary GitHub-hosted runner. Use only synthetic credentials
and reviewer-controlled services in this demonstration. The recovered helper
intentionally exits under the act-specific environment flag; a local marker run
cannot establish real GitHub privilege.

## Prepare, then optionally run the owned-fork experiment

Configure `GITHUB_TOKENS_USER_A` and `GITHUB_TOKENS_USER_B` locally for the two
owned demonstration accounts. Use `.secrets.template` only to prepare synthetic
values; do not place credentials in the package. From the repository root:

```sh
uv run pwnhunter attack \
  --input /tmp/owned-fixture-enumeration.json \
  --output /tmp/owned-fixture-prepared.json \
  --agent-provider gemini-cli \
  --agent-model gemini-3-flash-preview \
  --max-retries 1
```

This command prepares fork workspaces; it can create owned GitHub resources.
Read the generated agent prompt and configuration. Adding `--auto-execute`
runs the controller/agent workflow. An `--agent-timeout` of 1500 or 3600 seconds
matches values observed in archived logs, but neither is asserted as a universal
study configuration. The original model may be unavailable at reproduction time.

This process produces new demonstration artifacts. Do not add those transcripts,
generated payloads, repository identifiers or credentials to the review package.
