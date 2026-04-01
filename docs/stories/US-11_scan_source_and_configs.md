# US-11: Find package references in source and config files

## Persona

Both

## User Story

As a user, I want the scanner to find all source files that import the compromised package and all config files that reference it so that I know the full blast radius and can update pinned versions.

## Priority

Must Have

## Acceptance Criteria

- [ ] AC-1: Python source files (`.py`) are scanned for PyPI package imports (`import pkg`, `from pkg`, `pkg.method`).
- [ ] AC-2: JavaScript/TypeScript files (`.js`, `.ts`, `.mjs`, `.cjs`, `.jsx`, `.tsx`) are scanned for npm package imports (`require('pkg')`, `import from 'pkg'`).
- [ ] AC-3: Dependency config files (`pyproject.toml`, `requirements*.txt`, `package.json`, `package-lock.json`, `yarn.lock`, etc.) are scanned for package references.
- [ ] AC-4: Config files pinning to a compromised version are flagged with a clear "PINNED TO COMPROMISED VERSION" warning.
- [ ] AC-5: Results are grouped by file with line numbers and content shown.
- [ ] AC-6: The scanner's own source files are excluded from results.

## Notes

This phase helps Bob understand where the package is used across his codebase and which config files need version updates.
