"""Tests for phantom dependency detection (npm and PyPI).

Modules under test:
    scan_supply_chain.ecosystem_npm (lockfile parsing, node_modules walk)
    scan_supply_chain.ecosystem_pypi (site-packages walk)
"""

import json

from scan_supply_chain.ecosystem_npm import (
    NpmPlugin,
    _check_package_lock_json,
    _check_pnpm_lock,
    _check_yarn_lock,
)
from scan_supply_chain.ecosystem_pypi import PyPIPlugin


# ── npm: package-lock.json structural parsing ────────────────────────


class TestPackageLockJsonParsing:
    def test_finds_phantom_in_lockfile_v3_packages(self, tmp_path):
        # @req FR-17
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "node_modules/plain-crypto-js": {"version": "4.2.1"},
                        "node_modules/axios": {"version": "1.14.1"},
                    },
                }
            )
        )

        found = _check_package_lock_json(lockfile, ["plain-crypto-js"], set())

        assert len(found) == 1
        assert "plain-crypto-js@4.2.1" in found[0]

    def test_finds_phantom_in_lockfile_v1_dependencies(self, tmp_path):
        # @req FR-17
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(
            json.dumps(
                {
                    "lockfileVersion": 1,
                    "dependencies": {
                        "plain-crypto-js": {"version": "4.2.1"},
                        "axios": {"version": "1.14.1"},
                    },
                }
            )
        )

        found = _check_package_lock_json(lockfile, ["plain-crypto-js"], set())

        assert len(found) == 1
        assert "plain-crypto-js@4.2.1" in found[0]

    def test_ignores_packages_not_in_names_list(self, tmp_path):
        # @req FR-17
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(
            json.dumps(
                {
                    "packages": {
                        "node_modules/axios": {"version": "1.14.0"},
                    },
                }
            )
        )

        found = _check_package_lock_json(lockfile, ["plain-crypto-js"], set())

        assert found == []

    def test_deduplicates_via_seen_set(self, tmp_path):
        # @req FR-17
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text(
            json.dumps(
                {
                    "packages": {
                        "node_modules/plain-crypto-js": {"version": "4.2.1"},
                    },
                }
            )
        )

        seen = {f"{lockfile}:plain-crypto-js"}
        found = _check_package_lock_json(lockfile, ["plain-crypto-js"], seen)

        assert found == []

    def test_handles_malformed_json(self, tmp_path):
        # @req FR-17 NFR-03
        lockfile = tmp_path / "package-lock.json"
        lockfile.write_text("not json {{{")

        found = _check_package_lock_json(lockfile, ["plain-crypto-js"], set())

        assert found == []

    def test_handles_missing_file(self, tmp_path):
        # @req FR-17 NFR-03
        lockfile = tmp_path / "nonexistent.json"

        found = _check_package_lock_json(lockfile, ["plain-crypto-js"], set())

        assert found == []


# ── npm: yarn.lock line-anchored parsing ──────────────────────────────


class TestYarnLockParsing:
    def test_finds_phantom_at_line_start(self, tmp_path):
        # @req FR-17
        lockfile = tmp_path / "yarn.lock"
        lockfile.write_text(
            'plain-crypto-js@^4.2.1:\n  version "4.2.1"\n  resolved "..."\n'
        )

        found = _check_yarn_lock(lockfile, ["plain-crypto-js"], set())

        assert len(found) == 1
        assert "plain-crypto-js" in found[0]

    def test_ignores_substring_in_middle_of_line(self, tmp_path):
        # @req FR-17
        lockfile = tmp_path / "yarn.lock"
        lockfile.write_text('  resolved "https://registry/plain-crypto-js-4.2.1"\n')

        found = _check_yarn_lock(lockfile, ["plain-crypto-js"], set())

        assert found == []

    def test_finds_phantom_at_file_start(self, tmp_path):
        # @req FR-17
        lockfile = tmp_path / "yarn.lock"
        lockfile.write_text('plain-crypto-js@^4.2.1:\n  version "4.2.1"\n')

        found = _check_yarn_lock(lockfile, ["plain-crypto-js"], set())

        assert len(found) == 1

    def test_handles_missing_file(self, tmp_path):
        # @req FR-17 NFR-03
        lockfile = tmp_path / "nonexistent.lock"

        found = _check_yarn_lock(lockfile, ["plain-crypto-js"], set())

        assert found == []


# ── npm: pnpm-lock.yaml line-anchored parsing ─────────────────────────


class TestPnpmLockParsing:
    def test_finds_phantom_in_v6_format(self, tmp_path):
        # @req FR-17
        lockfile = tmp_path / "pnpm-lock.yaml"
        lockfile.write_text(
            "lockfileVersion: '6.0'\n"
            "packages:\n"
            "  /plain-crypto-js@4.2.1:\n"
            "    resolution: {integrity: sha512-abc}\n"
            "    dev: false\n"
        )

        found = _check_pnpm_lock(lockfile, ["plain-crypto-js"], set())

        assert len(found) == 1
        assert "plain-crypto-js" in found[0]

    def test_finds_phantom_in_v9_format(self, tmp_path):
        # @req FR-17
        lockfile = tmp_path / "pnpm-lock.yaml"
        lockfile.write_text(
            "lockfileVersion: '9.0'\n"
            "packages:\n"
            "  plain-crypto-js@4.2.1:\n"
            "    resolution: {integrity: sha512-abc}\n"
        )

        found = _check_pnpm_lock(lockfile, ["plain-crypto-js"], set())

        assert len(found) == 1
        assert "plain-crypto-js" in found[0]

    def test_ignores_packages_not_in_names_list(self, tmp_path):
        # @req FR-17
        lockfile = tmp_path / "pnpm-lock.yaml"
        lockfile.write_text(
            "lockfileVersion: '9.0'\n"
            "packages:\n"
            "  axios@1.14.0:\n"
            "    resolution: {integrity: sha512-xyz}\n"
        )

        found = _check_pnpm_lock(lockfile, ["plain-crypto-js"], set())

        assert found == []

    def test_handles_missing_file(self, tmp_path):
        # @req FR-17 NFR-03
        lockfile = tmp_path / "nonexistent.yaml"

        found = _check_pnpm_lock(lockfile, ["plain-crypto-js"], set())

        assert found == []

    def test_deduplicates_via_seen_set(self, tmp_path):
        # @req FR-17
        lockfile = tmp_path / "pnpm-lock.yaml"
        lockfile.write_text("packages:\n  /plain-crypto-js@4.2.1:\n    dev: false\n")

        seen = {f"{lockfile}:plain-crypto-js"}
        found = _check_pnpm_lock(lockfile, ["plain-crypto-js"], seen)

        assert found == []


# ── npm: full phantom dep walk (with pnpm) ────────────────────────────


class TestNpmPhantomDepWalkWithPnpm:
    def test_finds_phantom_in_pnpm_lock_during_walk(self, tmp_path):
        # @req FR-17
        project = tmp_path / "project"
        project.mkdir()
        (project / "pnpm-lock.yaml").write_text(
            "packages:\n  /plain-crypto-js@4.2.1:\n    dev: false\n"
        )

        plugin = NpmPlugin()
        found = plugin.find_phantom_deps(["plain-crypto-js"], [str(tmp_path)])

        assert len(found) == 1
        assert "plain-crypto-js" in found[0]


# ── npm: full phantom dep walk ────────────────────────────────────────


class TestNpmPhantomDepWalk:
    def test_finds_phantom_in_node_modules(self, tmp_path):
        # @req FR-17
        nm = tmp_path / "project" / "node_modules" / "plain-crypto-js"
        nm.mkdir(parents=True)

        plugin = NpmPlugin()
        found = plugin.find_phantom_deps(["plain-crypto-js"], [str(tmp_path)])

        assert len(found) == 1
        assert "plain-crypto-js" in found[0]

    def test_finds_phantom_in_lockfile_during_walk(self, tmp_path):
        # @req FR-17
        project = tmp_path / "project"
        project.mkdir()
        (project / "package-lock.json").write_text(
            json.dumps(
                {
                    "packages": {
                        "node_modules/plain-crypto-js": {"version": "4.2.1"},
                    },
                }
            )
        )

        plugin = NpmPlugin()
        found = plugin.find_phantom_deps(["plain-crypto-js"], [str(tmp_path)])

        assert len(found) == 1
        assert "4.2.1" in found[0]

    def test_returns_empty_when_no_phantom_deps(self, tmp_path):
        # @req FR-17
        nm = tmp_path / "project" / "node_modules" / "axios"
        nm.mkdir(parents=True)

        plugin = NpmPlugin()
        found = plugin.find_phantom_deps(["plain-crypto-js"], [str(tmp_path)])

        assert found == []

    def test_returns_empty_for_empty_names_list(self, tmp_path):
        # @req FR-17
        plugin = NpmPlugin()
        found = plugin.find_phantom_deps([], [str(tmp_path)])

        assert found == []


# ── PyPI: phantom dep detection in site-packages ─────────────────────


class TestPyPIPhantomDeps:
    def test_finds_phantom_dist_info(self, tmp_path):
        # @req FR-18
        sp = tmp_path / "lib" / "site-packages"
        (sp / "evil-pkg-1.0.0.dist-info").mkdir(parents=True)

        plugin = PyPIPlugin()
        found = plugin.find_phantom_deps(["evil-pkg"], [str(tmp_path)])

        assert len(found) == 1
        assert "evil-pkg" in found[0]

    def test_finds_phantom_egg_info(self, tmp_path):
        # @req FR-18
        sp = tmp_path / "lib" / "site-packages"
        (sp / "evil-pkg-1.0.0.egg-info").mkdir(parents=True)

        plugin = PyPIPlugin()
        found = plugin.find_phantom_deps(["evil-pkg"], [str(tmp_path)])

        assert len(found) == 1
        assert "evil-pkg" in found[0]

    def test_ignores_non_matching_packages(self, tmp_path):
        # @req FR-18
        sp = tmp_path / "lib" / "site-packages"
        (sp / "safe-pkg-2.0.0.dist-info").mkdir(parents=True)

        plugin = PyPIPlugin()
        found = plugin.find_phantom_deps(["evil-pkg"], [str(tmp_path)])

        assert found == []

    def test_returns_empty_for_empty_names(self, tmp_path):
        # @req FR-18
        plugin = PyPIPlugin()
        found = plugin.find_phantom_deps([], [str(tmp_path)])

        assert found == []
