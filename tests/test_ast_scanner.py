"""Tests for AST-based Python import detection.

Module under test: scan_supply_chain.ast_scanner
"""

from pathlib import Path

from scan_supply_chain.ast_scanner import scan_python_imports
from scan_supply_chain.models import SourceReference


class TestScanPythonImports:
    def _scan(
        self, source: str, package: str = "litellm"
    ) -> list[SourceReference] | None:
        lines = source.splitlines()
        return scan_python_imports(source, lines, package, "/test.py")

    def test_detects_import_statement(self) -> None:
        # @req FR-37
        refs = self._scan("import litellm\n")
        assert refs is not None
        assert len(refs) == 1
        assert refs[0].line_content == "import litellm"

    def test_detects_from_import(self) -> None:
        # @req FR-37
        refs = self._scan("from litellm import completion\n")
        assert refs is not None
        assert len(refs) == 1
        assert "from litellm" in refs[0].line_content

    def test_detects_from_submodule_import(self) -> None:
        # @req FR-37
        refs = self._scan("from litellm.utils import helper\n")
        assert refs is not None
        assert len(refs) == 1

    def test_detects_attribute_access(self) -> None:
        # @req FR-37
        refs = self._scan("import litellm\nx = litellm.completion('hi')\n")
        assert refs is not None
        assert len(refs) == 2

    def test_ignores_string_literal(self) -> None:
        # @req FR-38
        refs = self._scan('description = "litellm scanner"\n')
        assert refs == []

    def test_ignores_comment(self) -> None:
        # @req FR-38
        refs = self._scan("# import litellm\n")
        assert refs == []

    def test_ignores_regex_pattern(self) -> None:
        # @req FR-38
        refs = self._scan('PATTERN = re.compile(r"litellm\\.")\n')
        assert refs == []

    def test_ignores_quoted_package_name(self) -> None:
        # @req FR-38
        refs = self._scan("deps = ['litellm', 'flask']\n")
        assert refs == []

    def test_ignores_c2_domain_string(self) -> None:
        # @req FR-38
        refs = self._scan('C2_DOMAINS = ["models.litellm.cloud"]\n')
        assert refs == []

    def test_returns_none_on_syntax_error(self) -> None:
        # @req FR-37
        result = self._scan("import litellm\nthis { is broken\n")
        assert result is None

    def test_deduplicates_same_line(self) -> None:
        # @req FR-37
        refs = self._scan("import litellm; litellm.completion()\n")
        assert refs is not None
        # import and attribute access on same line → deduplicated
        line_numbers = [r.line_number for r in refs]
        assert len(line_numbers) == len(set(line_numbers))

    def test_empty_source(self) -> None:
        # @req FR-37
        refs = self._scan("")
        assert refs == []

    def test_file_without_package(self) -> None:
        # @req FR-37
        refs = self._scan("import os\nimport sys\n")
        assert refs == []

    def test_detects_import_submodule(self) -> None:
        # @req FR-37
        refs = self._scan("import litellm.proxy\n")
        assert refs is not None
        assert len(refs) == 1


class TestAstFallbackIntegration:
    def test_py_file_uses_ast_not_regex(self, tmp_path: Path) -> None:
        # @req FR-37 FR-38
        from scan_supply_chain.ecosystem_pypi import PyPIPlugin
        from scan_supply_chain.models import ScanResults
        from scan_supply_chain.source_scanner import scan_source_and_configs
        from tests.conftest import make_litellm_threat, make_scan_context

        # Create a .py file that mentions litellm in strings but doesn't import it
        scanner_like = tmp_path / "scanner_code.py"
        scanner_like.write_text(
            "import re\n"
            'PATTERN = re.compile(r"litellm\\.")\n'
            'C2 = ["models.litellm.cloud"]\n'
            'name = "litellm"\n'
        )

        threat = make_litellm_threat()
        results = ScanResults(compromised_versions=threat.compromised)
        ctx = make_scan_context(threat, PyPIPlugin(), [str(tmp_path)])

        scan_source_and_configs(results, ctx)

        # AST should produce zero results — no actual imports
        assert results.source_refs == []

    def test_py_file_with_real_import_detected(self, tmp_path: Path) -> None:
        # @req FR-37
        from scan_supply_chain.ecosystem_pypi import PyPIPlugin
        from scan_supply_chain.models import ScanResults
        from scan_supply_chain.source_scanner import scan_source_and_configs
        from tests.conftest import make_litellm_threat, make_scan_context

        real_usage = tmp_path / "app.py"
        real_usage.write_text("import litellm\nx = litellm.completion('hi')\n")

        threat = make_litellm_threat()
        results = ScanResults(compromised_versions=threat.compromised)
        ctx = make_scan_context(threat, PyPIPlugin(), [str(tmp_path)])

        scan_source_and_configs(results, ctx)

        assert len(results.source_refs) >= 1
        assert any("import litellm" in r.line_content for r in results.source_refs)
