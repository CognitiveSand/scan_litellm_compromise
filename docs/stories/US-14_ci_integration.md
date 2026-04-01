# US-14: Integrate scanner into CI/CD pipelines

## Persona

Alice

## User Story

As a SecOps engineer, I want to run the scanner in CI/CD pipelines and gate deployments on its exit code so that compromised dependencies are caught before reaching production.

## Priority

Should Have

## Acceptance Criteria

- [ ] AC-1: Exit code 0 means no compromise detected (CI passes).
- [ ] AC-2: Exit code 1 means at least one compromise detected (CI fails).
- [ ] AC-3: Exit code 2 means invalid arguments or missing files (CI fails with config error).
- [ ] AC-4: The scanner produces readable output on non-TTY terminals (ANSI codes disabled when stdout is not a TTY).
- [ ] AC-5: The scanner requires no interactive input — all configuration is via CLI flags.
- [ ] AC-6: The scanner has zero external dependencies, so it can be installed in minimal CI images without build tools.

## Notes

Alice adds `pip install scan-supply-chain && scan-supply-chain` to her CI pipeline. A failed scan blocks the deploy.
