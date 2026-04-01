# US-10: Detect Kubernetes lateral movement

## Persona

Alice

## User Story

As a SecOps engineer responsible for cluster security, I want the scanner to check for suspicious pods deployed by the malware so that I can detect lateral movement into Kubernetes infrastructure.

## Priority

Should Have

## Acceptance Criteria

- [ ] AC-1: When `kubectl` is available and the threat profile defines `pod_patterns`, the scanner queries pods in the specified namespace.
- [ ] AC-2: Pods matching the pattern prefix (e.g., `node-setup-`) are flagged as IOCs.
- [ ] AC-3: If `kubectl` is not installed, the check is silently skipped — no error, no crash.
- [ ] AC-4: If no `pod_patterns` are defined in the threat profile, the check is skipped entirely.

## Technical Constraints

Requires `kubectl` binary in `$PATH` with credentials configured for the target cluster. The scanner cannot inspect clusters it has no access to.

## Notes

The LiteLLM attack deploys privileged `node-setup-*` pods into `kube-system` that mount the host root filesystem. This is a critical escalation path.
