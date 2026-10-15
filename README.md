# Anonymous replication package

Start with [replication/README.md](replication/README.md). This export contains no
Git history, original live-target fixtures, or private input records.

Agent prompts preserve the research instructions with historical service
addresses replaced by runtime configuration placeholders. Set
`PWNHUNTER_HOOKBIN_URL` to your own reachable collector URL and
`PWNHUNTER_MEMDUMP_URL` to your own copy of the original helper before a
full owned-fork experiment. Local defaults are placeholders, not a deployment.
The recovered helper and its provenance are in `replication/helper/`.

The local synthetic marker suite and released statistical analyses work without
live model or GitHub access. `uv sync --locked --group dev` installs Python dependencies.
Node 24/npm and make are needed for all synthetic and mitigation tests.

The published source snapshot contains later maintenance changes. It is not a
claim of one fixed controller version for the entire study. Export changes:
configurable collector/helper URLs, anonymized author terms, and newly
constructed artificial unit-test inputs. Upstream project/license attributions
are retained.
