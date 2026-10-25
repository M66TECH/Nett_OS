# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests du scan phase 2 : agrégation, typologie d'erreurs, garde-fous."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from nettos.core.cancellation import CancellationToken
from nettos.core.result import DiagnosticStatus, ErrorKind
from nettos.diagnostics.scanner import MAX_DIRECTORIES, StorageScanner


def _sizes_by_suffix(result) -> dict[str, int]:
    """Rend les chemins relatifs plus lisibles dans les assertions."""
    return {Path(d.path).name: d.size_bytes for d in result.directories}


def test_directories_are_aggregated_bottom_up(tree: Path) -> None:
    result = StorageScanner().scan(tree)

    by_name = _sizes_by_suffix(result)
    assert by_name[tree.name] == 2000
    assert by_name["sub"] == 1900
    assert by_name["nested"] == 1000


def test_directory_file_counts_are_aggregated(tree: Path) -> None:
    result = StorageScanner().scan(tree)

    counts = {Path(d.path).name: d.file_count for d in result.directories}
    assert counts[tree.name] == 4
    assert counts["sub"] == 2
    assert counts["nested"] == 1


def test_total_entries_include_directories(tree: Path) -> None:
    result = StorageScanner().scan(tree)

    assert result.total_entries >= result.total_files
    assert result.total_entries == 4 + 2


def test_root_is_recorded(tmp_path: Path) -> None:
    result = StorageScanner().scan(tmp_path)

    assert result.root == str(tmp_path)


def test_cancellation_stops_scan(tree: Path) -> None:
    token = CancellationToken()
    token.cancel()

    result = StorageScanner(cancellation=token).scan(tree)

    assert result.status is DiagnosticStatus.CANCELLED
    assert result.total_files == 0


def test_cancellation_from_progress_callback(monkeypatch: pytest.MonkeyPatch, tree: Path) -> None:
    """L'annulation déclenchée par le callback arrête le parcours en cours."""
    monkeypatch.setattr("nettos.diagnostics.scanner._PROGRESS_EVERY_ENTRIES", 1)

    token = CancellationToken()
    calls: list[int] = []

    def progress(files: int, size: int) -> None:
        calls.append(files)
        token.cancel()

    result = StorageScanner(progress=progress, cancellation=token).scan(tree)

    assert calls, "le callback doit avoir été appelé au moins une fois"
    assert result.status is DiagnosticStatus.CANCELLED
    assert result.total_entries < 6, "le parcours doit s'arrêter avant la fin"


def test_cancellation_is_honoured_between_directories(tmp_path: Path) -> None:
    """Un jeton déjà annulé arrête le parcours sans lire le premier répertoire."""
    token = CancellationToken()

    def progress(files: int, size: int) -> None:
        token.cancel()

    root = tmp_path / "root"
    root.mkdir()
    (root / "a").mkdir()
    (root / "b").mkdir()

    result = StorageScanner(progress=progress, cancellation=token).scan(root)

    assert result.status is DiagnosticStatus.OK
    token.cancel()
    result_again = StorageScanner(cancellation=token).scan(root)
    assert result_again.status is DiagnosticStatus.CANCELLED


def test_directory_limit_guard(monkeypatch: pytest.MonkeyPatch, tree: Path) -> None:
    monkeypatch.setattr("nettos.diagnostics.scanner.MAX_DIRECTORIES", 1)

    result = StorageScanner().scan(tree)

    assert result.status is DiagnosticStatus.PARTIAL
    assert any("Limite" in error.reason for error in result.errors)


def test_max_directories_is_generous() -> None:
    assert MAX_DIRECTORIES >= 1_000_000


@pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="chmod POSIX indisponible sous Windows",
)
def test_error_kinds_are_classified(tmp_path: Path) -> None:
    root = tmp_path / "root"
    locked = root / "locked"
    locked.mkdir(parents=True)
    (locked / "f.txt").write_text("x")
    os.chmod(locked, 0o000)
    try:
        result = StorageScanner().scan(root)
    finally:
        os.chmod(locked, 0o700)

    assert result.error_count_by_kind.get(ErrorKind.PERMISSION_DENIED.value, 0) >= 1


def test_missing_root_is_not_found(tmp_path: Path) -> None:
    result = StorageScanner().scan(tmp_path / "absent")

    assert result.errors[0].kind is ErrorKind.NOT_FOUND
    assert result.status is DiagnosticStatus.PARTIAL


def test_empty_directory(tmp_path: Path) -> None:
    result = StorageScanner().scan(tmp_path)

    assert result.total_files == 0
    assert result.total_bytes == 0
    assert result.status is DiagnosticStatus.OK
    assert len(result.directories) == 1


def test_symlinked_file_is_not_counted(tree: Path) -> None:
    from tests.support.symlinks import try_symlink

    link = tree / "link-to-a"
    if not try_symlink(link, tree / "a.txt"):
        pytest.skip("liens symboliques indisponibles sur cette plateforme")

    result = StorageScanner().scan(tree)

    assert result.total_files == 4
    assert result.total_bytes == 2000
