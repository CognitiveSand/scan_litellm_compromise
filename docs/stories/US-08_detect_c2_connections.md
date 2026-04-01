# US-08: Detect active C2 network connections

## Persona

Alice

## User Story

As a SecOps engineer, I want the scanner to check for active network connections to known C2 infrastructure so that I can identify systems that are currently communicating with the attacker.

## Priority

Must Have

## Acceptance Criteria

- [ ] AC-1: By default, the scanner matches active connections against hardcoded known IPs from the threat profile — no DNS queries are made.
- [ ] AC-2: When C2 ports are specified in the threat profile, the scanner matches `ip:port` rather than bare IP substring.
- [ ] AC-3: `--resolve-c2` additionally performs live DNS resolution of C2 domains and adds the resolved IPs to the match set.
- [ ] AC-4: The network check uses the platform-appropriate tool (Linux: `ss`, macOS: `lsof`, Windows: `netstat`).
- [ ] AC-5: If the network tool is unavailable, the check is skipped gracefully with a message — not a crash.
- [ ] AC-6: Active C2 connections are flagged as IOCs and contribute to the compromised verdict.

## Notes

`--resolve-c2` has OPSEC implications — DNS queries to attacker-controlled domains reveal the investigation. The default (hardcoded IPs) is the safe choice.
