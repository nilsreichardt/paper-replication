## Controller Follow-up: Write Security Report

The repository is verified vulnerable based on controller evidence.
Write a high-quality markdown report at `REPORT.md` in the workspace root.
You are resuming the same conversation and have the full exploit history/context already.
Do not restate generic assumptions when repository-specific details are known from prior steps.

Use this structure exactly:
1. `### Summary`
2. `### Details`
3. `### PoC`
4. `### Impact`
5. `### Recommended Remediation`

For "Recommended Remediation", use something like this:

````markdown
### Recommended Remediation

#### 1. Stop using `pull_request_target` for untrusted code

Try to avoid using `pull_request_target` if possible. Switch:

```yml
on:
  pull_request_target:
```

to:

```yml
on:
  pull_request:
```

This ensures the workflow runs in the **fork’s security context** (no base repo secrets, restricted `GITHUB_TOKEN`).

#### 2. If retention of `pull_request_target` is necessary, secrets & checkout is required

Ensure it never checks out or executes untrusted PR code.
Use a safe-to-test label workflow, such as: [verify-safe-to-test-label](./replication/mitigation) GitHub Action.

This ensures untrusted code is *not* executed with secrets.

#### 3. Restrict `GITHUB_TOKEN` permissions

Add least-privilege permissions to all workflows:

```yml
permissions:
  contents: read
  # Grant write only where strictly necessary
```

and override only for specific jobs that truly require write access.
````

Requirements:
- Describe the vulnerable workflow behavior and trust-boundary issue.
- Include concrete evidence from your actual exploit/run history in this conversation.
- Keep remediation actionable and specific.
- Do not use markdown code fences around the whole file.

Repository: `{{repository_name}}`
Focused workflow: `{{focused_workflow}}`
Pull request URL: `{{pull_request_url}}`
Verification sources: `{{verification_sources}}`
Known `GITHUB_TOKEN` permission status: `{{github_token_permission_status}}`
Known write-scoped `GITHUB_TOKEN` permissions: `{{github_token_write_permissions}}`

Only include `GITHUB_TOKEN`-related details if the token is write-scoped. Read-only tokens are not considered vulnerable.
