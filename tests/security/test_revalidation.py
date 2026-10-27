# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests de sécurité de la revalidation anti-TOCTOU.

Ces tests couvrent les scénarios d'arborescences piégées exigés par la
section 10.2 : substitution de cible entre simulation et exécution, liens
symboliques, sortie de périmètre, disparition de fichier.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest
from tests.support.symlinks import try_symlink

from nettos.core.errors import PathOutsideAuthorizedRootError
from nettos.security.revalidation import (
    capture_snapshot,
    is_reparse_point_path,
    revalidate,
)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    base = tmp_path / "root"
    base.mkdir()
    return base


def _write(path: Path, content: bytes = b"hello") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


class TestSnapshot:
    def test_captures_regular_file(self, root: Path) -> None:
        target = _write(root / "a.txt", b"abc")

        snapshot = capture_snapshot(target)

        assert snapshot is not None
        assert snapshot.size_bytes == 3
        assert snapshot.file_id

    def test_returns_none_for_missing_file(self, root: Path) -> None:
        assert capture_snapshot(root / "absent.txt") is None

    def test_returns_none_for_symlink(self, root: Path) -> None:
        target = _write(root / "real.txt")
        link = root / "link.txt"
        if not try_symlink(link, target):
            pytest.skip("liens symboliques indisponibles")

        assert capture_snapshot(link) is None


class TestRevalidateAccepts:
    def test_unchanged_file_is_accepted(self, root: Path) -> None:
        target = _write(root / "a.txt")

        outcome = revalidate(capture_snapshot(target), root=root)

        assert outcome.accepted
        if outcome.file_descriptor is not None:
            os.close(outcome.file_descriptor)

    def test_can_close_descriptor_when_not_needed(self, root: Path) -> None:
        target = _write(root / "a.txt")

        outcome = revalidate(capture_snapshot(target), root=root, keep_open=False)

        assert outcome.accepted
        assert outcome.file_descriptor is None


class TestRevalidateRejects:
    def test_rejects_modified_content(self, root: Path) -> None:
        target = _write(root / "a.txt", b"hello")
        snapshot = capture_snapshot(target)
        target.write_bytes(b"changed content")

        outcome = revalidate(snapshot, root=root)

        assert not outcome.accepted
        assert "taille" in outcome.reason

    def test_rejects_same_size_different_mtime(self, root: Path) -> None:
        target = _write(root / "a.txt", b"hello")
        snapshot = capture_snapshot(target)
        future = time.time() + 3600
        os.utime(target, (future, future))

        outcome = revalidate(snapshot, root=root)

        assert not outcome.accepted
        assert "modification" in outcome.reason

    def test_rejects_deleted_file(self, root: Path) -> None:
        target = _write(root / "a.txt")
        snapshot = capture_snapshot(target)
        target.unlink()

        outcome = revalidate(snapshot, root=root)

        assert not outcome.accepted
        assert "disparu" in outcome.reason

    def test_rejects_symlink_substitution(self, root: Path) -> None:
        sensitive = _write(root / "sensitive.txt", b"secret")
        target = _write(root / "target.txt", b"hello")
        snapshot = capture_snapshot(target)
        target.unlink()
        if not try_symlink(target, sensitive):
            pytest.skip("liens symboliques indisponibles")

        outcome = revalidate(snapshot, root=root)

        assert not outcome.accepted
        assert "lien" in outcome.reason

    def test_rejects_replacement_by_directory(self, root: Path) -> None:
        target = _write(root / "a.txt")
        snapshot = capture_snapshot(target)
        target.unlink()
        target.mkdir()

        outcome = revalidate(snapshot, root=root)

        assert not outcome.accepted

    def test_rejects_outside_authorized_root(self, tmp_path: Path) -> None:
        root = tmp_path / "root"
        root.mkdir()
        outside = _write(tmp_path / "outside.txt")

        with pytest.raises(PathOutsideAuthorizedRootError):
            revalidate(capture_snapshot(outside), root=root)

    def test_rejects_file_replaced_by_another(self, root: Path) -> None:
        first = _write(root / "a.txt", b"11111")
        snapshot = capture_snapshot(first)
        first.unlink()
        _write(first, b"11111")

        outcome = revalidate(snapshot, root=root)

        assert not outcome.accepted
        assert "remplacé" in outcome.reason or "date" in outcome.reason


class TestRaceScenarios:
    def test_substitution_between_snapshot_and_revalidate(self, root: Path) -> None:
        original = _write(root / "victim.txt", b"data")
        attacker = _write(root / "attacker.txt", b"data")
        snapshot = capture_snapshot(original)

        original.unlink()
        os.replace(attacker, original)

        outcome = revalidate(snapshot, root=root)

        assert not outcome.accepted

    def test_repeated_revalidation_is_stable(self, root: Path) -> None:
        target = _write(root / "a.txt")
        snapshot = capture_snapshot(target)

        first = revalidate(snapshot, root=root, keep_open=False)
        second = revalidate(snapshot, root=root, keep_open=False)

        assert first.accepted and second.accepted


class TestReparsePointHelper:
    def test_regular_file_is_not_reparse_point(self, root: Path) -> None:
        target = _write(root / "a.txt")

        assert not is_reparse_point_path(target)

    def test_missing_path_is_not_reparse_point(self, root: Path) -> None:
        assert not is_reparse_point_path(root / "absent")


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX only")
def test_rejects_symlinked_parent_directory(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = _write(outside / "secret.txt", b"secret")

    link_dir = root / "escape"
    if not try_symlink(link_dir, outside, directory=True):
        pytest.skip("liens symboliques indisponibles")

    snapshot = capture_snapshot(link_dir / "secret.txt")
    assert snapshot is not None

    with pytest.raises(PathOutsideAuthorizedRootError):
        revalidate(snapshot, root=root)
    assert victim.exists()


def test_rejects_target_reached_through_directory_junction(tmp_path: Path) -> None:
    """Une junction NTFS ne doit pas permettre d'atteindre l'extérieur.

    ``capture_snapshot`` peut réussir (le fichier final n'est pas un lien),
    mais la résolution du chemin le ramène hors du périmètre : la cible est
    refusée avant toute action.
    """
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = _write(outside / "secret.txt", b"secret")

    link_dir = root / "junction"
    if not try_symlink(link_dir, outside, directory=True):
        pytest.skip("junctions indisponibles sur cette plateforme")

    snapshot = capture_snapshot(link_dir / "secret.txt")
    if snapshot is None:
        pytest.skip("chemin non capturable via junction sur cette plateforme")

    with pytest.raises(PathOutsideAuthorizedRootError):
        revalidate(snapshot, root=root)
    assert victim.exists()
