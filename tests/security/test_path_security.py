# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests de sécurité du socle.

Critère d'arrêt (section 10.2) : aucune cible ne doit être atteignable
hors périmètre. Les scénarios d'arborescences piégées s'étendront au
moteur de nettoyage en phases 3 à 4.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from nettos.core.errors import PathOutsideAuthorizedRootError, UnsupportedPlatformError
from nettos.diagnostics.scanner import StorageScanner
from nettos.security.path_policy import resolve_no_symlinks


def _make_symlink(link: Path, target: Path, *, directory: bool = False) -> bool:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError):
        return False
    return True


def test_symlink_escape_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "authorized"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("sensible")

    link = root / "link"
    if not _make_symlink(link, outside):
        pytest.skip("liens symboliques indisponibles sur cette plateforme")

    with pytest.raises(PathOutsideAuthorizedRootError):
        resolve_no_symlinks(link, root=root)


def test_scanner_ignores_symlink_into_sensitive_area(tmp_path: Path) -> None:
    root = tmp_path / "authorized"
    root.mkdir()
    sensitive = tmp_path / "sensitive"
    sensitive.mkdir()
    (sensitive / "secret.txt").write_text("x" * 5000)

    if not _make_symlink(root / "evil", sensitive, directory=True):
        pytest.skip("liens symboliques indisponibles sur cette plateforme")

    result = StorageScanner().scan(root)

    assert result.total_files == 0
    assert result.total_bytes == 0


def test_path_with_spaces_and_unicode(tmp_path: Path) -> None:
    root = tmp_path / "racine autorisée"
    root.mkdir()
    target = root / "dossier é à ü" / "fichier avec espaces.txt"
    target.parent.mkdir()
    target.write_text("x" * 42)

    result = StorageScanner().scan(root)

    assert result.total_files == 1
    assert result.total_bytes == 42


def test_permission_denied_is_reported_not_crashed(tmp_path: Path) -> None:
    if sys.platform.startswith("win"):
        pytest.skip("les ACL Windows ne reproduisent pas chmod POSIX simplement")

    root = tmp_path / "root"
    locked = root / "locked"
    locked.mkdir(parents=True)
    (locked / "inside.txt").write_text("x")
    os.chmod(locked, 0o000)
    try:
        result = StorageScanner().scan(root)
    finally:
        os.chmod(locked, 0o700)

    assert result.error_count >= 1
    assert result.status.value == "partial"


def test_scanner_never_writes(tree_integrity_check: None) -> None:
    """Le scanner est en lecture seule : aucune opération d'écriture."""
    assert tree_integrity_check is None


@pytest.fixture
def tree_integrity_check(tmp_path: Path) -> None:
    """Le scanner laisse l'arborescence strictement inchangée."""
    root = tmp_path / "scan-me"
    root.mkdir()
    (root / "file.txt").write_text("contenu")
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}

    StorageScanner().scan(root)

    after = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    assert before == after


def test_unsupported_platform_adapter_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    from nettos.adapters import factory

    monkeypatch.setattr(factory.sys, "platform", "darwin")

    with pytest.raises(UnsupportedPlatformError):
        factory.get_platform_adapter()
