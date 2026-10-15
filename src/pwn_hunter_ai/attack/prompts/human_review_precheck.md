Classify whether this case should be human reviewed based only on this criterion. A human review is required if one of the following criteria apply:
- A trust gate exists before untrusted PR code execution.

Trust gate examples: maintainer approval, trusted member checks, safe-to-test labels, allowlists, manual dispatch checks.

If none of the above criteria apply, return `needs_human_review: false` (e.g. no trust gate exists).

ONLY ONE OF THESE CRITERIA APPLY A HUMAN REVIEW IS REQUIRED. MOST OF THE TIME, THIS WILL NOT BE THE CASE.

Return strict JSON with keys `needs_human_review` (boolean) and `reason` (short).

AI analysis JSON{{request_context}}:
{{ai_analysis_json}}
