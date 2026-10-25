# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests de la correspondance de motifs (cibles et exclusions)."""

from __future__ import annotations

import pytest

from nettos.cleaners.simulation import (
    CompiledPattern,
    compile_pattern,
    matches_exclusion,
    matches_pattern,
)

# Sémantique retenue : « ** » = zéro ou plusieurs segments (style .gitignore).
CASES: list[tuple[str, str, bool]] = [
    ("a.tmp", "*.tmp", True),
    ("a.log", "*.tmp", False),
    ("sub/a.tmp", "*.tmp", True),
    ("a", "**/*", True),
    ("a/b/c", "**/*", True),
    ("x.yaml", "**/*", True),
    ("pip/x", "**/pip/**", True),
    ("cache/pip", "**/pip/**", True),
    ("a/pip", "**/pip/**", True),
    ("pip", "**/pip/**", True),
    ("a/pipx", "**/pip/**", False),
    ("foo/baz.log", "foo/**/*.log", True),
    ("foo/a/b/baz.log", "foo/**/*.log", True),
    ("foo/bar/baz.txt", "foo/**/*.log", False),
    ("other/baz.log", "foo/**/*.log", False),
    ("thumbcache_32.db", "thumbcache_*.db", True),
    ("other.db", "thumbcache_*.db", False),
    ("info/a.trashinfo", "info/*.trashinfo", True),
    ("info/sub/a.trashinfo", "info/*.trashinfo", False),
    ("d/deep/a.dmp", "**/*.dmp", True),
    ("a.dmp", "**/*.dmp", True),
    ("a.dmp.bak", "**/*.dmp", False),
    ("files/x/locked", "files/**/*", True),
    ("files/locked", "files/**/*", True),
    ("other/locked", "files/**/*", False),
]


@pytest.mark.parametrize(("path", "pattern", "expected"), CASES)
def test_matches_pattern(path: str, pattern: str, expected: bool) -> None:
    assert matches_pattern(path, pattern) is expected


@pytest.mark.parametrize(("path", "pattern", "expected"), CASES)
def test_compiled_matches_like_facade(path: str, pattern: str, expected: bool) -> None:
    assert compile_pattern(pattern).matches(path) is expected


def test_wildcards_do_not_cross_separators() -> None:
    assert not matches_pattern("a/b/c.txt", "a/*.txt")


def test_double_star_crosses_separators() -> None:
    assert matches_pattern("a/b/c.txt", "a/**/c.txt")


def test_literal_pattern_matches_exact_name() -> None:
    assert matches_pattern("temp.ini", "temp.ini")
    assert not matches_pattern("other.ini", "temp.ini")


def test_windows_separators_are_normalized() -> None:
    assert matches_pattern("cache\\pip\\x", "**/pip/**")


class TestMatchesExclusion:
    def test_returns_matching_exclusion(self) -> None:
        exclusions = ("**/pip/**", "**/ccache/**")

        assert matches_exclusion("a/pip/b", exclusions) == "**/pip/**"

    def test_returns_none_when_no_match(self) -> None:
        assert matches_exclusion("a/b", ("**/pip/**",)) is None

    def test_exclusion_wins_on_directory_name(self) -> None:
        assert matches_exclusion("npm", ("**/npm/**",)) is not None


class TestCompiledPattern:
    def test_pattern_property_is_normalized(self) -> None:
        assert CompiledPattern("a\\b\\c").pattern == "a/b/c"

    def test_cache_returns_same_instance(self) -> None:
        assert compile_pattern("*.tmp") is compile_pattern("*.tmp")

    def test_empty_relative_path_matches_leading_double_star(self) -> None:
        # « ** » accepte zéro segment : un chemin vide satisfait « **/* ».
        assert matches_pattern("", "**/*") is True


def test_long_path_is_fast() -> None:
    """Une profondeur élevée ne doit pas provoquer d'explosion combinatoire."""
    deep = "/".join(["d"] * 60) + "/file.tmp"

    assert matches_pattern(deep, "**/*.tmp")
    assert matches_pattern(deep, "**/file.tmp")
