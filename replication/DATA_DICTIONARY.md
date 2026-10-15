# Released data

The raw disclosure and verification files are not distributed. The release is
derived through an explicit allowlist in `scripts/export_data.py`. Repository
names, source and fork URLs, scanned commit hashes, run IDs, workflow paths,
timestamps, free-text sinks, secret names/values, agent transcripts, and generated
exploits are withheld. Hashing repository names or commit IDs would not hide them
from enumeration and is deliberately avoided.

Each CSV is a separate per-repository projection. There are no identifiers,
stable row orders or join keys. Each view is independently shuffled. Do not join
views by row position: positions have no correspondence. Stars and contributors
are bucketed; activity and creation dates are reduced to study categories.
Different taxonomy types are also unlinked to avoid releasing rare type sets.

Every complete category tuple in a CSV occurs at least five times. Smaller cells
are omitted from that CSV, but are included in the corresponding aggregate JSON
so the published marginal counts remain reproducible. Aggregate cells carry no
row identifiers. This is a disclosure-minimization measure, not a formal
guarantee against re-identification using arbitrary outside information.

| View | Fields besides outcome | Definition |
| --- | --- | --- |
| outcomes | none | One outcome per examined repository |
| stars | star_bucket | 0, 1–10, 11–100, 101–1000, >1000, unknown |
| activity | activity | active: enumeration commit timestamp >= April 2024; inactive: earlier; unknown: no timestamp |
| token_scope | token_scope | Highest workflow-level category: write > non-write > read > not-clear > unknown |
| credential_evidence | write_scoped, named_secret | 0/1 indicators used in corrected classification; excludes seeded canaries from named secrets |
| contributors | contributor_bucket | 0–1, 2–5, 6–10, 11–50, 51–100, >100, unknown; only successful enrichment records |
| creation_token | creation_cohort, write_scoped | pre-February-2023, from-February-2023, or unknown; coarse creation cohort versus write scope |
| verification_status | verification_status | error, skipped, or processed from repository-level controller flags; no free-text errors |
| sink_availability | has_structured_sink | 0/1 for any structured agent sink; privileged/RCE only; distinguishes the strict no-sink residual from any missing-sink finding |
| taxonomy_* | present | 0/1 for this type; only privileged and RCE outcomes; each view is independent |

`outcome` is `privileged`, `rce`, or `unconfirmed`. The RCE class can include
local-only act confirmation and does not establish privilege. Unconfirmed does
not mean safe. `named_secret` indicates a named-secret execution path confirmed
with synthetic values on owned forks; it is not a captured live credential.
For the precise classifier and sink mapping, see the source in `../scripts/`.

`*.aggregate.json` lists complete categorical cells and their counts, before
CSV small-cell suppression. `contributors_summary.json` contains class-level
sample size, median and a coarse lower threshold for the maximum; exact maxima
are withheld because they can identify outlier repositories.
`export_audit.json` records input coverage, discrepancies, schema, and suppression
counts. Missing inputs are reported; they are not silently inferred from the paper.

The published Stage 1 denominator (95,584) is retained as a documented paper
constant in the reproduction report and agrees with the 95,584 GitHub
repositories retained from the supplied Stage 1 list.

These views reproduce the released marginal analyses, not arbitrary multivariate
analyses or an independent reclassification from withheld exploit evidence.
