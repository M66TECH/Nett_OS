# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests unitaires des contrôles de chemin (protection anti-évasion)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from nettos.core.errors import PathOutsideAuthorizedRootError
from nettos.security.path_policy import is_within_root, resolve_no_symlinks


def test_root_is_within_itself(tmp_path: Path) -> None:
    assert is_within_root(tmp_path, tmp_path)


def test_child_is_within_root(tmp_path: Path) -> None:
    assert is_within_root(tmp_path / "sub" / "file.txt", tmp_path)


def test_sibling_prefix_is_not_within_root(tmp_path: Path) -> None:
    root = tmp_path / "cache"
    escape = tmp_path / "cache-evil"
    root.mkdir()
    escape.mkdir()

    assert not is_within_root(escape, root)


def test_parent_is_not_within_root(tmp_path: Path) -> None:
    root = tmp_path / "a" / "b"
    root.mkdir(parents=True)

    assert not is_within_root(tmp_path / "a", root)


def test_traversal_is_not_within_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()

    assert not is_within_root(root / ".." / "outside.txt", root)


def test_resolve_no_symlinks_returns_path(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "file.txt"
    target.parent.mkdir()
    target.write_text("x")

    assert resolve_no_symlinks(target, root=tmp_path) == target.resolve()


def test_resolve_no_symlinks_rejects_escape(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("x")

    with pytest.raises(PathOutsideAuthorizedRootError):
        resolve_no_symlinks(outside, root=root)


@pytest.mark.skipif(sys.platform.startswith("win") is False, reason="test Windows only")
def test_case_insensitivity_on_windows(tmp_path: Path) -> None:
    root = tmp_path / "Cache"
    root.mkdir()

    assert is_within_root(tmp_path / "cache", root)
