# US-09: Detect phantom dependencies

## Persona

Alice

## User Story

As a SecOps engineer investigating a supply chain attack that injected a malicious transitive dependency, I want the scanner to flag packages that should not exist (e.g., `plain-crypto-js` from the axios attack) so that I can detect attacks that operate via dependency injection rather than direct package modification.

## Priority

Must Have

## Acceptance Criteria

- [ ] AC-1: For npm, phantom dependencies are detected by checking for their directory in `node_modules/`.
- [ ] AC-2: For npm, `package-lock.json` is parsed structurally as JSON (not substring search) to detect phantom deps in lockfile entries.
- [ ] AC-3: For npm, `yarn.lock` is checked via line-anchored matching for phantom dep entries.
- [ ] AC-4: For PyPI, phantom dependencies are detected by checking for their `dist-info`/`egg-info` in `site-packages/`.
- [ ] AC-5: Each found phantom dependency is reported with its location and, when available, its resolved version.

## Notes

Phantom dependencies are a hallmark of the axios attack pattern (injected `plain-crypto-js@4.2.1`). This detection path is distinct from compromised-version detection.
