# US-15: Opt into live C2 DNS resolution

## Persona

Alice

## User Story

As a SecOps engineer who suspects the attacker has rotated C2 infrastructure since the last scanner update, I want to enable live DNS resolution so that connections to new IPs for known C2 domains are also detected.

## Priority

Nice to Have

## Acceptance Criteria

- [ ] AC-1: `--resolve-c2` causes the scanner to perform `gethostbyname()` on each C2 domain in the threat profile.
- [ ] AC-2: Resolved IPs are added to the match set alongside the hardcoded known IPs (not replacing them).
- [ ] AC-3: If DNS resolution fails for a domain (NXDOMAIN, timeout), the scanner continues with the hardcoded IPs — no crash.
- [ ] AC-4: A visible NOTE is printed when `--resolve-c2` is active, warning the user about OPSEC implications.
- [ ] AC-5: Without `--resolve-c2`, no DNS queries are made to attacker-controlled domains.

## Notes

This flag has real OPSEC risk: DNS queries to attacker-controlled domains reveal the investigation. Alice uses it only when she has reason to believe IPs have rotated and she's on a network where the query won't tip off the attacker.
