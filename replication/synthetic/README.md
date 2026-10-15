# Artificial A–F examples

These six projects were created for this replication package. They are not
historical study targets or evidence of the agent's measured effectiveness.
Every payload prints a fixed marker and checks only a synthetic canary. It does
not extract memory, transmit data, or contain real repository identities.

| Type | Pathway | Workflow execution |
| --- | --- | --- |
| A | Package-manager lifecycle hook | npm install invokes postinstall |
| B | Test-suite execution | pytest imports and runs a test |
| C | Build-system invocation | make executes a build recipe |
| D | Direct script invocation | bash executes ci.sh |
| E | Interpreter execution | Python executes main.py |
| F | Transitive action checkout | Trusted local composite action checks out PR head, then executes Python |

Run `uv run python replication/scripts/run_synthetic.py` from the repository
root. The runner uses each workflow's actual execution command in an isolated
temporary directory. For each case it also neutralizes the attacker-controlled
file and confirms that the marker disappears. These checks exercise execution
pathways locally; they do not emulate GitHub Actions privilege boundaries,
static-scanner findings or an autonomous agent.

The YAML files deliberately demonstrate unsafe checkout patterns. They are
nested under this directory and cannot run as this repository's own workflows.
They contain no secret references and declare read-only permissions.

For an owned GitHub demonstration, copy exactly one fixture's contents into a
new, isolated repository you own. Case B includes its Python setup and pytest installation steps.
Open a pull request from a second owned fork and change its marker file. The
workflow's logs should show that marker. No secret or write permission is
needed to demonstrate this code path. Do not add production credentials.

To demonstrate Stage 2, enumerate only that reviewer-owned repository with the
vendored Gato-X tool and hand its finding to the pipeline. The vendored scanner uses the author-recalled `multiple-tokens` branch.
Full Stage 3 confirmation additionally requires the documented collector, the
recovered memory helper, credentials, and model access. The local
marker tests must not be described as full pipeline end-to-end verification.

See `../OWNED_DEMO.md` for the complete owned-repository setup sequence.
