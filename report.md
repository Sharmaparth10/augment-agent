# Security Vulnerability Report: Command Injection in `augment-agent`

## Report Metadata
- Reporter: `<your name or handle>`
- Date discovered: `2026-02-17`
- Product: `augmentcode/augment-agent` (GitHub Action source repo)
- Affected component: CLI execution path in `src/index.ts`
- Vulnerability type: OS Command Injection
- CWE: `CWE-78: Improper Neutralization of Special Elements used in an OS Command`
- Confidence: High (confirmed with controlled reproduction)
- Exploit maturity: Proof of Concept completed
- Disclosure intent: Private/responsible disclosure

## Executive Summary
The action constructs a single shell command string from user-controlled inputs and executes it with `shell: true`.  
Because shell expansion still occurs inside double quotes, crafted input (for example `$(...)`) is evaluated by the shell before the target binary executes. This enables arbitrary command execution in the GitHub Actions runner context.

## Affected Code
- `src/index.ts:25` builds `fullCommand` by concatenating command and args.
- `src/index.ts:35` calls `spawn(fullCommand, [], ...)`.
- `src/index.ts:37` sets `shell: true`.
- Untrusted input sources flow into args:
  - `src/index.ts:125` `--instruction`
  - `src/index.ts:122` `--instruction-file`
  - `src/index.ts:118` `--model`
  - `src/index.ts:133` `--rules`
  - `src/index.ts:144` `--mcp-config`

## Root Cause
The implementation:
1. Concatenates potentially attacker-influenced arguments into one shell command string.
2. Executes through a shell (`shell: true`).
3. Uses quote escaping that does not prevent shell command substitution like `$(...)`.

This is a classic command-construction anti-pattern.

## Proof of Concept (Confirmed)
I confirmed this in a fork with a safe, non-destructive test workflow:
- File: `.github/workflows/security-shell-injection-poc.yml`
- Payload passed to `INPUT_INSTRUCTION`:
  - `poc $(touch /tmp/augment_agent_poc_marker)`
- Result:
  - Workflow printed: `VULNERABLE: marker file exists; command substitution executed.`
  - Job failed intentionally with exit code `1` to signal confirmed vulnerability.

This demonstrates that injected shell substitution executes on runner.

## Attack Scenario
### Preconditions
- Attacker can influence action inputs (directly or indirectly via workflow, templates, repository content, PR data flow, or wrapper actions).
- Vulnerable action version is used.

### Attack Path
`Input influence -> shell command string construction -> shell expansion executes injected command -> arbitrary runner command execution`

### Potential Impact
- Exfiltration of environment secrets/tokens available to the job.
- Unauthorized GitHub API actions using job token permissions.
- Tampering with build/review output and CI integrity.
- Pivoting within CI steps (download/run additional payloads, modify artifacts, alter logs).

Impact severity increases with token scope and workflow permissions.

## Severity Assessment
- Recommended severity: **High**.
- Suggested CVSS v3.1 (example): `8.6`  
  Vector example: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L`

Notes:
- Exact score depends on real deployment patterns and permission model.
- If maintainers can show no attacker-controlled input path in production usage, score may be adjusted. The vulnerable primitive is still present and confirmed.

## Remediation
### Primary Fix
Avoid invoking a shell. Pass command and arguments directly.

Current vulnerable pattern:
```ts
const child = spawn(fullCommand, [], { shell: true, stdio: 'inherit' });
```

Recommended safe pattern:
```ts
const child = spawn(command, args, { shell: false, stdio: 'inherit', ...options });
```

### Additional Hardening
- Remove custom manual quoting logic entirely.
- Constrain/validate path-like args (`instruction_file`, `rules`, `mcp_configs`) if needed by threat model.
- Add regression test/CI check ensuring payloads like `$(touch /tmp/poc)` are treated as literal strings.

## Post-Fix Validation Plan
1. Patch `execCommand` to use argument-array spawn without shell.
2. Re-run the PoC workflow.
3. Expected result after fix:
   - Marker file is **not** created.
   - Final step prints `NOT_REPRODUCED: marker file does not exist.`
4. Add/keep regression workflow or unit test to prevent reintroduction.

## Responsible Disclosure Notes
- Submit privately through GitHub Security Advisory (preferred) or project security contact.
- Include:
  - This report
  - PoC workflow path
  - PoC run URL and log snippet
  - File/line references listed above
- Do not publish exploit details publicly before maintainer coordination.

## Evidence Checklist (fill before submission)
- [ ] PoC run URL:
- [ ] Screenshot/log line with `VULNERABLE: marker file exists...`:
- [ ] Commit hash tested:
- [ ] Action version/tag tested:
- [ ] Any environmental constraints observed:

