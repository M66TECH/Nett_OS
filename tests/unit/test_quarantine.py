# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests du moteur de quarantaine (section 6.3)."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

from nettos.cleaners.quarantine import (
    STATE_DELETED,
    STATE_QUARANTINED,
    Quarantine,
    _sha256_of,
    default_quarantine_root,
)


@pytest.fixture
def quarantine(tmp_path: Path) -> Quarantine:
    return Quarantine(tmp_path / "quarantine")


@pytest.fixture
def victim(tmp_path: Path) -> Path:
    path = tmp_path / "data.bin"
    path.write_bytes(b"important data" * 100)
    return path


class TestStore:
    def test_moves_file_to_quarantine(self, quarantine: Quarantine, victim: Path) -> None:
        entry = quarantine.store(
            victim, rule_identifier="test.rule", rule_version="1", size_bytes=1400
        )

        assert entry.state == STATE_QUARANTINED
        assert entry.reversible
        assert not victim.exists()
        assert Path(entry.stored_path).is_file()

    def test_records_metadata(self, quarantine: Quarantine, victim: Path) -> None:
        digest = _sha256_of(victim)

        entry = quarantine.store(
            victim, rule_identifier="test.rule", rule_version="2", size_bytes=1400
        )

        assert entry.sha256 == digest
        assert entry.rule_identifier == "test.rule"
        assert entry.rule_version == "2"
        assert entry.original_path == str(victim)

    def test_metadata_is_persisted_as_json(self, quarantine: Quarantine, victim: Path) -> None:
        entry = quarantine.store(
            victim, rule_identifier="test.rule", rule_version="1", size_bytes=1400
        )

        meta = quarantine.root / "metadata" / f"{entry.entry_id}.json"
        payload = json.loads(meta.read_text(encoding="utf-8"))
        assert payload["entry_id"] == entry.entry_id
        assert payload["state"] == STATE_QUARANTINED

    def test_entries_are_listed_newest_first(self, quarantine: Quarantine, tmp_path: Path) -> None:
        for index in range(3):
            path = tmp_path / f"f{index}.bin"
            path.write_bytes(b"x")
            quarantine.store(path, rule_identifier="r", rule_version="1", size_bytes=1)

        entries = quarantine.entries()

        assert len(entries) == 3
        timestamps = [entry.created_at for entry in entries]
        assert timestamps == sorted(timestamps, reverse=True)


class TestRestore:
    def test_restores_original_path(self, quarantine: Quarantine, victim: Path) -> None:
        entry = quarantine.store(victim, rule_identifier="r", rule_version="1", size_bytes=1400)

        restored = quarantine.restore(entry.entry_id)

        assert restored == victim
        assert victim.is_file()

    def test_restore_preserves_content(self, quarantine: Quarantine, victim: Path) -> None:
        original = victim.read_bytes()
        entry = quarantine.store(victim, rule_identifier="r", rule_version="1", size_bytes=1400)

        quarantine.restore(entry.entry_id)

        assert victim.read_bytes() == original

    def test_metadata_is_removed_after_restore(self, quarantine: Quarantine, victim: Path) -> None:
        entry = quarantine.store(victim, rule_identifier="r", rule_version="1", size_bytes=1400)

        quarantine.restore(entry.entry_id)

        assert quarantine.entries() == []

    def test_restore_refuses_existing_destination(
        self, quarantine: Quarantine, victim: Path
    ) -> None:
        entry = quarantine.store(victim, rule_identifier="r", rule_version="1", size_bytes=1400)
        victim.write_bytes(b"new file at same place")

        with pytest.raises(FileExistsError):
            quarantine.restore(entry.entry_id)

    def test_restore_can_overwrite_when_asked(self, quarantine: Quarantine, victim: Path) -> None:
        entry = quarantine.store(victim, rule_identifier="r", rule_version="1", size_bytes=1400)
        victim.write_bytes(b"replacement")

        quarantine.restore(entry.entry_id, overwrite=True)

        assert victim.read_bytes() != b"replacement"

    def test_restore_unknown_entry_raises(self, quarantine: Quarantine) -> None:
        with pytest.raises(FileNotFoundError):
            quarantine.restore("unknown")


class TestDeletionRecord:
    def test_records_irreversible_deletion(self, quarantine: Quarantine) -> None:
        entry = quarantine.record_deletion(
            original_path="/some/path.bin",
            rule_identifier="r",
            rule_version="1",
            size_bytes=42,
        )

        assert entry.state == STATE_DELETED
        assert not entry.reversible
        assert entry.stored_path == ""

    def test_irreversible_entry_cannot_be_restored(self, quarantine: Quarantine) -> None:
        entry = quarantine.record_deletion(
            original_path="/some/path.bin",
            rule_identifier="r",
            rule_version="1",
            size_bytes=42,
        )

        with pytest.raises(FileNotFoundError):
            quarantine.restore(entry.entry_id)


class TestPurge:
    def test_purge_removes_all_entries(self, quarantine: Quarantine, tmp_path: Path) -> None:
        for index in range(3):
            path = tmp_path / f"f{index}.bin"
            path.write_bytes(b"x" * 10)
            quarantine.store(path, rule_identifier="r", rule_version="1", size_bytes=10)

        report = quarantine.purge()

        assert report.removed_entries == 3
        assert report.removed_bytes == 30
        assert quarantine.entries() == []

    def test_purge_with_age_keeps_recent_entries(
        self, quarantine: Quarantine, victim: Path
    ) -> None:
        entry = quarantine.store(victim, rule_identifier="r", rule_version="1", size_bytes=1400)

        report = quarantine.purge(older_than_days=30)

        assert report.removed_entries == 0
        assert quarantine.get(entry.entry_id) is not None

    def test_purge_old_entries_with_lowered_timestamp(
        self, quarantine: Quarantine, victim: Path
    ) -> None:
        entry = quarantine.store(victim, rule_identifier="r", rule_version="1", size_bytes=1400)
        meta = quarantine.root / "metadata" / f"{entry.entry_id}.json"
        payload = json.loads(meta.read_text(encoding="utf-8"))
        old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=60)
        payload["created_at"] = old.isoformat()
        meta.write_text(json.dumps(payload), encoding="utf-8")

        report = quarantine.purge(older_than_days=30)

        assert report.removed_entries == 1


class TestDefaults:
    def test_default_root_is_under_user_data(self) -> None:
        root = default_quarantine_root()

        assert root.is_absolute()
        assert "NettOS" in str(root)
        assert root.name == "quarantine"


class TestCorruptedMetadata:
    def test_corrupted_json_is_ignored(self, quarantine: Quarantine) -> None:
        quarantine.ensure()
        (quarantine.root / "metadata" / "broken.json").write_text("{not json")

        assert quarantine.entries() == []

    def test_get_returns_none_for_unknown(self, quarantine: Quarantine) -> None:
        assert quarantine.get("missing") is None
