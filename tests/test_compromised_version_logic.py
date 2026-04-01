"""Tests for the core domain logic: is this version compromised?

Module under test: scan_supply_chain.models
"""

from scan_supply_chain.models import (
    ConfigReference,
    Installation,
    ScanResults,
    SourceReference,
)

from tests.conftest import LITELLM_COMPROMISED


# ── ScanResults.compromised_installations ──────────────────────────────


class TestCompromisedInstallationsFiltering:
    def test_version_1_82_7_is_compromised(self):
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            installations=[Installation(env_path="/env", version="1.82.7")],
        )
        assert len(results.compromised_installations) == 1

    def test_version_1_82_8_is_compromised(self):
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            installations=[Installation(env_path="/env", version="1.82.8")],
        )
        assert len(results.compromised_installations) == 1

    def test_version_1_82_6_is_not_compromised(self):
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            installations=[Installation(env_path="/env", version="1.82.6")],
        )
        assert len(results.compromised_installations) == 0

    def test_version_1_83_0_is_not_compromised(self):
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            installations=[Installation(env_path="/env", version="1.83.0")],
        )
        assert len(results.compromised_installations) == 0

    def test_empty_version_is_not_compromised(self):
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            installations=[Installation(env_path="/env", version="")],
        )
        assert len(results.compromised_installations) == 0

    def test_version_with_leading_whitespace_is_not_compromised(self):
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            installations=[Installation(env_path="/env", version=" 1.82.7")],
        )
        assert len(results.compromised_installations) == 0

    def test_mixed_installations_filters_only_compromised(self):
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            installations=[
                Installation(env_path="/a", version="1.82.7"),
                Installation(env_path="/b", version="1.82.6"),
                Installation(env_path="/c", version="1.82.8"),
            ],
        )
        compromised = results.compromised_installations
        assert len(compromised) == 2

    def test_no_installations_returns_empty_list(self):
        results = ScanResults(compromised_versions=LITELLM_COMPROMISED)
        assert results.compromised_installations == []

    def test_only_safe_installations_returns_empty_list(self):
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            installations=[
                Installation(env_path="/a", version="1.80.0"),
                Installation(env_path="/b", version="1.82.6"),
            ],
        )
        assert results.compromised_installations == []


# ── ScanResults.compromised_configs ────────────────────────────────────


class TestCompromisedConfigsFiltering:
    def test_pinned_to_1_82_7_is_compromised(self):
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            config_refs=[
                ConfigReference("r.txt", 1, "litellm==1.82.7", "1.82.7"),
            ],
        )
        assert len(results.compromised_configs) == 1

    def test_pinned_to_1_82_8_is_compromised(self):
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            config_refs=[
                ConfigReference("r.txt", 1, "litellm==1.82.8", "1.82.8"),
            ],
        )
        assert len(results.compromised_configs) == 1

    def test_pinned_to_safe_version_is_not_compromised(self):
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            config_refs=[
                ConfigReference("r.txt", 1, "litellm==1.82.6", "1.82.6"),
            ],
        )
        assert len(results.compromised_configs) == 0

    def test_no_pinned_version_is_not_compromised(self):
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            config_refs=[
                ConfigReference("r.txt", 1, "litellm>=1.80", None),
            ],
        )
        assert len(results.compromised_configs) == 0

    def test_mixed_configs_filters_only_compromised(self):
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            config_refs=[
                ConfigReference("a.txt", 1, "litellm==1.82.7", "1.82.7"),
                ConfigReference("b.txt", 1, "litellm==1.80.0", "1.80.0"),
            ],
        )
        assert len(results.compromised_configs) == 1
        assert results.compromised_configs[0].pinned_version == "1.82.7"

    def test_no_configs_returns_empty_list(self):
        results = ScanResults(compromised_versions=LITELLM_COMPROMISED)
        assert results.compromised_configs == []


# ── ScanResults.is_clean ───────────────────────────────────────────────


class TestScanResultsIsClean:
    def test_clean_when_no_issues(self):
        results = ScanResults(compromised_versions=LITELLM_COMPROMISED)
        assert results.is_clean is True

    def test_clean_with_safe_installations(self):
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            installations=[Installation(env_path="/a", version="1.82.6")],
        )
        assert results.is_clean is True

    def test_not_clean_when_compromised_installation_present(self):
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            installations=[Installation(env_path="/a", version="1.82.7")],
        )
        assert results.is_clean is False

    def test_not_clean_when_ioc_present(self):
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            iocs=["/tmp/pglog"],
        )
        assert results.is_clean is False

    def test_not_clean_when_compromised_config_present(self):
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            config_refs=[
                ConfigReference("r.txt", 1, "litellm==1.82.8", "1.82.8"),
            ],
        )
        assert results.is_clean is False

    def test_clean_with_source_refs_but_no_compromise(self):
        results = ScanResults(
            compromised_versions=LITELLM_COMPROMISED,
            source_refs=[
                SourceReference("/app.py", 1, "import litellm"),
            ],
        )
        assert results.is_clean is True


# ── ScanResults.source_files / config_files deduplication ──────────────


class TestScanResultsFileDeduplication:
    def test_source_files_deduplicates_by_path(self):
        results = ScanResults(
            source_refs=[
                SourceReference("/app.py", 1, "import litellm"),
                SourceReference("/app.py", 5, "litellm.completion()"),
                SourceReference("/other.py", 3, "import litellm"),
            ]
        )
        assert results.source_files == {"/app.py", "/other.py"}

    def test_config_files_deduplicates_by_path(self):
        results = ScanResults(
            config_refs=[
                ConfigReference("r.txt", 1, "litellm==1.80", "1.80.0"),
                ConfigReference("r.txt", 5, "litellm>=1.0", None),
                ConfigReference("p.toml", 3, '"litellm"', None),
            ]
        )
        assert results.config_files == {"r.txt", "p.toml"}

    def test_source_files_empty_when_no_refs(self):
        assert ScanResults().source_files == set()

    def test_config_files_empty_when_no_refs(self):
        assert ScanResults().config_files == set()
