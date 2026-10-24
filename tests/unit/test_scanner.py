# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests unitaires du scanner de stockage en lecture seule."""

from __future__ import annotations

from pathlib import Path

import pytest

from nettos.core.result import DiagnosticStatus
from nettos.diagnostics.scanner import StorageScanner


def test_scan_counts_files_and_bytes(tree: Path) -> None:
    result = StorageScanner().scan(tree)

    assert result.total_files == 4
    assert result.total_bytes == 2000
    assert result.error_count == 0
    assert result.status is DiagnosticStatus.OK


def test_scan_does_not_modify_tree(tree: Path) -> None:
    before = sorted(p.relative_to(tree) for p in tree.rglob("*"))
    StorageScanner().scan(tree)
    after = sorted(p.relative_to(tree) for p in tree.rglob("*"))

    assert before == after


def test_scan_missing_root_reports_error(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"

    result = StorageScanner().scan(missing)

    assert result.total_files == 0
    assert result.error_count == 1
    assert result.status is DiagnosticStatus.PARTIAL
    assert "inexistant" in result.errors[0].reason


def test_scan_progress_is_reported(tree: Path) -> None:
    seen: list[tuple[int, int]] = []

    StorageScanner(progress=lambda files, size: seen.append((files, size))).scan(tree)

    assert seen
    assert seen[-1][0] >= seen[0][0]


@pytest.mark.skipif(
    not hasattr(Path, "symlink_to"),
    reason="les liens symboliques ne sont pas disponibles",
)
def test_scan_does_not_follow_symlinks(tree: Path) -> None:
    link = tree / "link-to-sub"
    try:
        link.symlink_to(tree / "sub", target_is_directory=True)
    except OSError:
        pytest.skip("création de lien symbolique non autorisée sur cette plateforme")

    result = StorageScanner().scan(tree)

    assert result.total_files == 4
    assert result.total_bytes == 2000
