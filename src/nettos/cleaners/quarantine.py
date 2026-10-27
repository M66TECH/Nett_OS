# SPDX-License-Identifier: AGPL-3.0-or-later
"""Quarantaine minimale (cahier des charges, section 6.3).

Déplacer un fichier vers un répertoire de quarantaine accompagné d'un
enregistrement de métadonnées plutôt que le supprimer immédiatement permet
une restauration tant que la quarantaine n'est pas purgée.

Le module reste **honnête sur ses limites** :

- la quarantaine n'est **pas une sauvegarde** ;
- elle est impossible dans certains cas (volume différent, permissions
  insuffisantes) ; l'opération est alors signalée comme **irréversible**
  avant confirmation ;
- sur un même volume, le déplacement utilise un renommage atomique, ce qui
  réduit fortement la fenêtre de risque.

Aucune promesse de restauration universelle : l'entrée marque explicitement
son état (``quarantined`` ou ``deleted``).
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import os
import shutil
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal

STATE_QUARANTINED = "quarantined"
STATE_DELETED = "deleted"

EventState = Literal["quarantined", "deleted"]

DEFAULT_RETENTION_DAYS = 30


@dataclass(slots=True)
class QuarantineEntry:
    """Enregistrement d'une cible déplacée (ou supprimée) en quarantaine."""

    entry_id: str
    original_path: str
    stored_path: str
    rule_identifier: str
    rule_version: str
    size_bytes: int
    sha256: str | None
    created_at: str
    state: str
    reversible: bool
    note: str = ""

    def as_dict(self) -> dict[str, object]:
        """Sérialisation JSON stable."""
        return asdict(self)


@dataclass(slots=True)
class PurgeReport:
    """Résultat d'une purge de quarantaine."""

    removed_entries: int = 0
    removed_bytes: int = 0
    failed: list[str] = field(default_factory=list)


class Quarantine:
    """Répertoire de quarantaine, indexé par fichiers de métadonnées JSON."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._files = self._root / "files"
        self._metadata = self._root / "metadata"

    @property
    def root(self) -> Path:
        """Racine de la quarantaine."""
        return self._root

    def ensure(self) -> None:
        """Crée l'arborescence de quarantaine si nécessaire."""
        self._files.mkdir(parents=True, exist_ok=True)
        self._metadata.mkdir(parents=True, exist_ok=True)

    def store(
        self,
        source: Path,
        *,
        rule_identifier: str,
        rule_version: str,
        size_bytes: int,
        original_path: str | None = None,
        note: str = "",
    ) -> QuarantineEntry:
        """Déplace ``source`` en quarantaine et écrit ses métadonnées.

        Tente d'abord un renommage atomique (même volume). En cas d'échec
        (volumes différents), tente une copie puis vérifie l'empreinte avant
        de supprimer l'original. Si aucune voie sûre n'existe, l'entrée est
        enregistrée en état ``deleted`` et ``reversible`` vaut ``False`` :
        l'appelant doit l'avoir annoncé avant confirmation.
        """
        self.ensure()
        entry_id = uuid.uuid4().hex
        digest = _sha256_of(source)
        stored = self._files / entry_id
        created_at = dt.datetime.now(dt.timezone.utc).isoformat()

        origin = original_path or str(source)
        reversible = True
        state = STATE_QUARANTINED
        final_note = note

        try:
            os.replace(source, stored)
        except OSError:
            reversible, state, final_note = self._fallback_copy_then_delete(
                source, stored, digest, note
            )

        entry = QuarantineEntry(
            entry_id=entry_id,
            original_path=origin,
            stored_path=str(stored),
            rule_identifier=rule_identifier,
            rule_version=rule_version,
            size_bytes=size_bytes,
            sha256=digest,
            created_at=created_at,
            state=state,
            reversible=reversible,
            note=final_note,
        )
        self._write_metadata(entry)
        return entry

    def record_deletion(
        self,
        *,
        original_path: str,
        rule_identifier: str,
        rule_version: str,
        size_bytes: int,
        note: str = "",
    ) -> QuarantineEntry:
        """Enregistre une suppression irréversible (quarantaine impossible)."""
        self.ensure()
        entry = QuarantineEntry(
            entry_id=uuid.uuid4().hex,
            original_path=original_path,
            stored_path="",
            rule_identifier=rule_identifier,
            rule_version=rule_version,
            size_bytes=size_bytes,
            sha256=None,
            created_at=dt.datetime.now(dt.timezone.utc).isoformat(),
            state=STATE_DELETED,
            reversible=False,
            note=note or "quarantaine impossible : suppression définitive",
        )
        self._write_metadata(entry)
        return entry

    def entries(self) -> list[QuarantineEntry]:
        """Toutes les entrées enregistrées, de la plus récente à la plus ancienne."""
        if not self._metadata.is_dir():
            return []
        entries: list[QuarantineEntry] = []
        for meta in self._metadata.glob("*.json"):
            try:
                payload = json.loads(meta.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            try:
                entries.append(QuarantineEntry(**payload))
            except TypeError:
                continue
        entries.sort(key=lambda entry: entry.created_at, reverse=True)
        return entries

    def get(self, entry_id: str) -> QuarantineEntry | None:
        """Retourne une entrée par identifiant."""
        path = self._metadata / f"{entry_id}.json"
        if not path.is_file():
            return None
        try:
            return QuarantineEntry(**json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError, TypeError):
            return None

    def restore(self, entry_id: str, *, overwrite: bool = False) -> Path:
        """Restaure une entrée à son emplacement d'origine.

        Lève :class:`FileNotFoundError` si l'entrée n'existe pas ou si le
        fichier n'est plus en quarantaine, et :class:`FileExistsError` si la
        destination est occupée et que ``overwrite`` est faux.
        """
        entry = self.get(entry_id)
        if entry is None:
            raise FileNotFoundError(f"entrée de quarantaine inconnue : {entry_id}")
        if entry.state != STATE_QUARANTINED or not entry.reversible:
            raise FileNotFoundError(
                f"l'entrée {entry_id} n'est pas restaurable (état : {entry.state})"
            )

        source = Path(entry.stored_path)
        if not source.is_file():
            raise FileNotFoundError(f"fichier de quarantaine absent : {source}")

        destination = Path(entry.original_path)
        if destination.exists() and not overwrite:
            raise FileExistsError(f"la destination existe déjà : {destination}")

        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.replace(source, destination)
        except OSError:
            shutil.move(str(source), str(destination))

        self._delete_metadata(entry_id)
        return destination

    def purge(self, *, older_than_days: float | None = None) -> PurgeReport:
        """Purge la quarantaine, éventuellement au-delà d'un âge donné.

        Sans argument, purge **tout** : la confirmation explicite relève de
        l'appelant, jamais de ce module.
        """
        report = PurgeReport()
        now = dt.datetime.now(dt.timezone.utc)

        for entry in self.entries():
            if older_than_days is not None:
                try:
                    created = dt.datetime.fromisoformat(entry.created_at)
                except ValueError:
                    created = now
                if (now - created).days < older_than_days:
                    continue

            stored = Path(entry.stored_path) if entry.stored_path else None
            if stored is not None and stored.is_file():
                try:
                    stored.unlink()
                except OSError as exc:
                    report.failed.append(f"{entry.entry_id} : {exc}")
                    continue
                report.removed_entries += 1
                report.removed_bytes += entry.size_bytes
            self._delete_metadata(entry.entry_id)

        return report

    def _fallback_copy_then_delete(
        self, source: Path, stored: Path, digest: str | None, note: str
    ) -> tuple[bool, str, str]:
        """Copie puis supprime, en vérifiant l'empreinte avant suppression."""
        try:
            shutil.copy2(source, stored)
        except OSError as exc:
            return False, STATE_DELETED, f"copie impossible ({exc}) : {note}".strip()

        if digest is not None and _sha256_of(stored) != digest:
            with contextlib.suppress(OSError):
                stored.unlink()
            return False, STATE_DELETED, f"empreinte divergente après copie : {note}".strip()

        try:
            source.unlink()
        except OSError as exc:
            with contextlib.suppress(OSError):
                stored.unlink()
            return False, STATE_DELETED, f"suppression impossible ({exc}) : {note}".strip()

        return True, STATE_QUARANTINED, note

    def _write_metadata(self, entry: QuarantineEntry) -> None:
        path = self._metadata / f"{entry.entry_id}.json"
        path.write_text(
            json.dumps(entry.as_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _delete_metadata(self, entry_id: str) -> None:
        path = self._metadata / f"{entry_id}.json"
        with contextlib.suppress(OSError):
            path.unlink()


def _sha256_of(path: Path) -> str | None:
    """Empreinte SHA-256 d'un fichier, ou ``None`` si illisible."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def default_quarantine_root() -> Path:
    """Emplacement par défaut de la quarantaine, dans les données utilisateur.

    Utilise ``%LOCALAPPDATA%`` sous Windows et ``$XDG_DATA_HOME`` sous Linux,
    conformément aux conventions de chaque plateforme.
    """
    import sys

    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "NettOS" / "quarantine"


__all__ = [
    "DEFAULT_RETENTION_DAYS",
    "STATE_DELETED",
    "STATE_QUARANTINED",
    "PurgeReport",
    "Quarantine",
    "QuarantineEntry",
    "default_quarantine_root",
]
