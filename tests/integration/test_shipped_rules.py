# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests des règles livrées, exécutées sur des arborescences factices.

On instancie chaque nettoyeur avec un « profil » temporaire : la règle est
la vraie, seules les racines changent. Cela vérifie le comportement réel
des motifs et exclusions sans toucher au profil de l'utilisateur.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from nettos.cleaners.registry import CleanerRegistry
from nettos.cleaners.rules_linux import ThumbnailCacheCleaner, UserCacheCleaner, UserTrashCleaner
from nettos.cleaners.rules_windows import (
    WindowsCrashDumpCleaner,
    WindowsTempCleaner,
    WindowsThumbnailCacheCleaner,
)


def _age(path: Path, days: int) -> None:
    stamp = time.time() - days * 86_400
    for entry in path.rglob("*"):
        if entry.is_file():
            os.utime(entry, (stamp, stamp))


class TestUserCacheCleaner:
    def test_excludes_compile_caches(self, tmp_path: Path) -> None:
        cache = tmp_path / ".cache"
        (cache / "app").mkdir(parents=True)
        (cache / "ccache").mkdir()
        (cache / "pip").mkdir()
        (cache / "app" / "data.bin").write_bytes(b"x" * 300)
        (cache / "ccache" / "obj.o").write_bytes(b"x" * 300)
        (cache / "pip" / "wheel.whl").write_bytes(b"x" * 300)
        _age(tmp_path, 30)

        result = UserCacheCleaner(home=tmp_path).simulate()

        names = {Path(c.path).name for c in result.candidates}
        assert "data.bin" in names
        assert "obj.o" not in names
        assert "wheel.whl" not in names

    def test_recent_files_are_skipped(self, tmp_path: Path) -> None:
        cache = tmp_path / ".cache"
        cache.mkdir()
        (cache / "fresh.bin").write_bytes(b"x")

        result = UserCacheCleaner(home=tmp_path).simulate()

        assert result.file_count == 0

    def test_missing_cache_reports_root(self, tmp_path: Path) -> None:
        result = UserCacheCleaner(home=tmp_path).simulate()

        assert result.missing_roots == [str(tmp_path / ".cache")]


class TestThumbnailCacheCleaner:
    def test_only_image_thumbnails(self, tmp_path: Path) -> None:
        thumbs = tmp_path / ".cache" / "thumbnails"
        (thumbs / "normal").mkdir(parents=True)
        (thumbs / "normal" / "a.png").write_bytes(b"x" * 10)
        (thumbs / "normal" / "b.jpg").write_bytes(b"x" * 10)
        (thumbs / "normal" / "notes.txt").write_bytes(b"x" * 10)

        result = ThumbnailCacheCleaner(home=tmp_path).simulate()

        names = {Path(c.path).name for c in result.candidates}
        assert names == {"a.png", "b.jpg"}


class TestUserTrashCleaner:
    def test_trash_files_and_metadata(self, tmp_path: Path) -> None:
        trash = tmp_path / ".local" / "share" / "Trash"
        (trash / "files").mkdir(parents=True)
        (trash / "info").mkdir()
        (trash / "files" / "doc.txt").write_bytes(b"x" * 50)
        (trash / "info" / "doc.txt.trashinfo").write_bytes(b"x" * 20)

        result = UserTrashCleaner(home=tmp_path).simulate()

        names = {Path(c.path).name for c in result.candidates}
        assert names == {"doc.txt", "doc.txt.trashinfo"}

    def test_expunged_is_excluded(self, tmp_path: Path) -> None:
        trash = tmp_path / ".local" / "share" / "Trash"
        (trash / "expunged").mkdir(parents=True)
        (trash / "expunged" / "gone.txt").write_bytes(b"x")

        result = UserTrashCleaner(home=tmp_path).simulate()

        assert result.file_count == 0


class TestWindowsTempCleaner:
    def test_only_old_files_in_temp(self, tmp_path: Path) -> None:
        temp = tmp_path / "AppData" / "Local" / "Temp"
        temp.mkdir(parents=True)
        (temp / "old.tmp").write_bytes(b"x" * 100)
        (temp / "fresh.tmp").write_bytes(b"x" * 100)
        stamp = time.time() - 30 * 86_400
        os.utime(temp / "old.tmp", (stamp, stamp))

        result = WindowsTempCleaner(profile=tmp_path).simulate()

        names = {Path(c.path).name for c in result.candidates}
        assert names == {"old.tmp"}

    def test_lock_files_are_excluded(self, tmp_path: Path) -> None:
        temp = tmp_path / "AppData" / "Local" / "Temp"
        temp.mkdir(parents=True)
        (temp / "installer.tmp.lock").write_bytes(b"x")
        _age(tmp_path, 30)

        result = WindowsTempCleaner(profile=tmp_path).simulate()

        assert result.file_count == 0


class TestWindowsThumbnailCacheCleaner:
    def test_thumbcache_files_are_found(self, tmp_path: Path) -> None:
        explorer = tmp_path / "AppData" / "Local" / "Microsoft" / "Windows" / "Explorer"
        explorer.mkdir(parents=True)
        (explorer / "thumbcache_32.db").write_bytes(b"x" * 10)
        (explorer / "thumbcache_256.db").write_bytes(b"x" * 10)
        (explorer / "iconcache.db").write_bytes(b"x" * 10)

        result = WindowsThumbnailCacheCleaner(profile=tmp_path).simulate()

        names = {Path(c.path).name for c in result.candidates}
        assert names == {"thumbcache_32.db", "thumbcache_256.db"}


class TestWindowsCrashDumpCleaner:
    def test_only_old_dumps(self, tmp_path: Path) -> None:
        dumps = tmp_path / "AppData" / "Local" / "CrashDumps"
        dumps.mkdir(parents=True)
        (dumps / "old.dmp").write_bytes(b"x" * 100)
        (dumps / "new.dmp").write_bytes(b"x" * 100)
        stamp = time.time() - 40 * 86_400
        os.utime(dumps / "old.dmp", (stamp, stamp))

        result = WindowsCrashDumpCleaner(profile=tmp_path).simulate()

        names = {Path(c.path).name for c in result.candidates}
        assert names == {"old.dmp"}


class TestShippedRegistryIsSimulable:
    def test_every_active_rule_simulates_without_error(self) -> None:
        registry = CleanerRegistry()

        for entry in registry.active_entries():
            result = registry.instantiate(entry.identifier or "").simulate()
            assert result.rule_identifier == entry.identifier

    def test_simulation_is_deterministic(self) -> None:
        registry = CleanerRegistry()
        entry = registry.active_entries()[0]
        cleaner = registry.instantiate(entry.identifier or "")

        first = cleaner.simulate()
        second = cleaner.simulate()

        assert first.file_count == second.file_count
        assert first.total_bytes == second.total_bytes


@pytest.mark.skipif(
    not os.path.isdir(os.path.expanduser("~")),
    reason="pas de répertoire personnel",
)
def test_simulation_never_touches_real_profile() -> None:
    """Garde-fou : simuler sur le vrai profil ne modifie rien."""
    registry = CleanerRegistry()
    entries = registry.active_entries()
    if not entries:
        pytest.skip("aucune règle active")

    cleaner = registry.instantiate(entries[0].identifier or "")
    before = _profile_fingerprint()
    cleaner.simulate()
    after = _profile_fingerprint()

    assert before == after


def _profile_fingerprint() -> dict[str, int]:
    """Empreinte légère du profil : nombre de fichiers de premier niveau."""
    home = Path.home()
    fingerprint: dict[str, int] = {}
    for name in (".cache", ".local", "AppData"):
        base = home / name
        if base.exists():
            try:
                fingerprint[name] = sum(1 for _ in base.iterdir())
            except OSError:
                fingerprint[name] = -1
    return fingerprint
