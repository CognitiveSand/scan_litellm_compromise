"""Tests for search root deduplication.

Module under test: scan_supply_chain.search_roots
"""

from pathlib import Path

from scan_supply_chain.search_roots import deduplicate_roots


class TestDeduplicateRoots:
    def test_removes_child_when_parent_present(self, tmp_path: Path) -> None:
        # @req FR-13 NFR-14
        parent = tmp_path / "home"
        child = parent / "me"
        child.mkdir(parents=True)

        result = deduplicate_roots([str(parent), str(child)])

        assert result == [str(parent)]

    def test_removes_deep_child(self, tmp_path: Path) -> None:
        # @req FR-13 NFR-14
        root = tmp_path / "opt"
        deep = root / "conda" / "envs" / "myenv"
        deep.mkdir(parents=True)

        result = deduplicate_roots([str(root), str(deep)])

        assert result == [str(root)]

    def test_keeps_independent_roots(self, tmp_path: Path) -> None:
        # @req FR-13
        a = tmp_path / "home"
        b = tmp_path / "opt"
        a.mkdir()
        b.mkdir()

        result = deduplicate_roots([str(a), str(b)])

        assert len(result) == 2

    def test_removes_symlink_that_resolves_under_parent(self, tmp_path: Path) -> None:
        # @req FR-13
        real = tmp_path / "home" / "me"
        real.mkdir(parents=True)
        link = tmp_path / "link_to_me"
        link.symlink_to(real)

        result = deduplicate_roots([str(tmp_path / "home"), str(link)])

        assert len(result) == 1

    def test_ignores_nonexistent_dirs(self, tmp_path: Path) -> None:
        # @req FR-13
        exists = tmp_path / "real"
        exists.mkdir()

        result = deduplicate_roots([str(exists), str(tmp_path / "nope")])

        assert result == [str(exists)]

    def test_empty_input(self) -> None:
        # @req FR-13
        assert deduplicate_roots([]) == []
