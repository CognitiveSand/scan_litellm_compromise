# US-12: Receive actionable remediation steps

## Persona

Bob

## User Story

As a junior employee who found a compromise, I want the scanner to tell me exactly what to do — step by step, specific to my platform — so that I can begin remediation without waiting for a senior engineer.

## Priority

Must Have

## Acceptance Criteria

- [ ] AC-1: When compromise is detected, the report includes numbered remediation steps.
- [ ] AC-2: If `rotate_secrets` is true in the threat profile, the first step instructs the user to rotate SSH keys, cloud credentials, API keys, and tokens.
- [ ] AC-3: Platform-specific artifact removal instructions are shown (e.g., different paths for Linux vs. Windows).
- [ ] AC-4: The safe package install command from the threat profile is shown (e.g., `pip install litellm==1.82.6`).
- [ ] AC-5: Config files pinned to compromised versions are listed with file path, line number, and the offending line.
- [ ] AC-6: Persistence check commands are shown for the current platform.
- [ ] AC-7: The advisory URL from the threat profile is shown for further reference.

## Notes

Bob should be able to follow these steps without understanding the attack's technical details. The guidance must be self-contained and safe to execute.
