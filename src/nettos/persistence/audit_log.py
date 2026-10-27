# SPDX-License-Identifier: AGPL-3.0-or-later
"""Journal d'audit local (SQLite).

Politique de confidentialité appliquée telle qu'arbitrée en section 5.2 :

- les chemins **concernés par une opération de nettoyage** sont enregistrés
  (c'est l'usage utile de la traçabilité) ;
- les chemins simplement parcourus lors d'une analyse ne le sont pas ;
- le **contenu** des fichiers n'est jamais enregistré ;
- tout reste local, aucun export sans action explicite de l'utilisateur ;
- la rétention est paramétrable, avec purge automatique et purge manuelle.

Ce module n'expose aucune fonction réseau : c'est une garantie structurelle,
vérifiable par inspection.
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_info (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS operations (
    operation_id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    rule_identifier TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    targets INTEGER NOT NULL DEFAULT 0,
    processed INTEGER NOT NULL DEFAULT 0,
    quarantined INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    theoretical_bytes INTEGER NOT NULL DEFAULT 0,
    reclaimed_bytes INTEGER NOT NULL DEFAULT 0,
    error_summary TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS operation_targets (
    operation_id TEXT NOT NULL,
    path TEXT NOT NULL,
    outcome TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (operation_id) REFERENCES operations (operation_id)
);

CREATE INDEX IF NOT EXISTS idx_operations_started
    ON operations (started_at);

CREATE INDEX IF NOT EXISTS idx_targets_operation
    ON operation_targets (operation_id);
"""


@dataclass(slots=True)
class OperationRecord:
    """Une opération de nettoyage consignée."""

    operation_id: str
    started_at: str
    finished_at: str | None
    rule_identifier: str
    rule_version: str
    mode: str
    status: str
    targets: int
    processed: int
    quarantined: int
    failed: int
    theoretical_bytes: int
    reclaimed_bytes: int
    error_summary: dict[str, int]


@dataclass(slots=True)
class TargetRecord:
    """Une cible d'opération consignée."""

    operation_id: str
    path: str
    outcome: str
    reason: str
    size_bytes: int


class AuditLog:
    """Accès au journal d'audit local."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(str(self._path))
        self._connection.row_factory = sqlite3.Row
        self._connection.executescript(_SCHEMA)
        self._ensure_version()
        self._connection.commit()

    @property
    def path(self) -> Path:
        """Chemin du fichier de journal."""
        return self._path

    def close(self) -> None:
        """Ferme la connexion."""
        self._connection.close()

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def start_operation(
        self,
        *,
        operation_id: str,
        rule_identifier: str,
        rule_version: str,
        mode: str,
        targets: int,
        theoretical_bytes: int,
    ) -> None:
        """Ouvre une opération ; son issue sera consignée à la clôture."""
        self._connection.execute(
            """
            INSERT INTO operations (
                operation_id, started_at, rule_identifier, rule_version,
                mode, status, targets, theoretical_bytes
            ) VALUES (?, ?, ?, ?, ?, 'running', ?, ?)
            """,
            (
                operation_id,
                dt.datetime.now(dt.timezone.utc).isoformat(),
                rule_identifier,
                rule_version,
                mode,
                targets,
                theoretical_bytes,
            ),
        )
        self._connection.commit()

    def finish_operation(
        self,
        operation_id: str,
        *,
        status: str,
        processed: int,
        quarantined: int,
        failed: int,
        reclaimed_bytes: int,
        error_summary: dict[str, int],
    ) -> None:
        """Clôture l'opération avec ses compteurs réels."""
        self._connection.execute(
            """
            UPDATE operations SET
                finished_at = ?, status = ?, processed = ?, quarantined = ?,
                failed = ?, reclaimed_bytes = ?, error_summary = ?
            WHERE operation_id = ?
            """,
            (
                dt.datetime.now(dt.timezone.utc).isoformat(),
                status,
                processed,
                quarantined,
                failed,
                reclaimed_bytes,
                json.dumps(error_summary, ensure_ascii=False),
                operation_id,
            ),
        )
        self._connection.commit()

    def record_target(
        self,
        operation_id: str,
        *,
        path: str,
        outcome: str,
        reason: str = "",
        size_bytes: int = 0,
    ) -> None:
        """Consigne une cible traitée (jamais son contenu)."""
        self._connection.execute(
            """
            INSERT INTO operation_targets (operation_id, path, outcome, reason, size_bytes)
            VALUES (?, ?, ?, ?, ?)
            """,
            (operation_id, path, outcome, reason, size_bytes),
        )

    def record_targets(self, records: list[TargetRecord]) -> None:
        """Consigne un lot de cibles en une transaction."""
        self._connection.executemany(
            """
            INSERT INTO operation_targets (operation_id, path, outcome, reason, size_bytes)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (record.operation_id, record.path, record.outcome, record.reason, record.size_bytes)
                for record in records
            ],
        )
        self._connection.commit()

    def operations(self, limit: int = 50) -> list[OperationRecord]:
        """Opérations récentes, de la plus récente à la plus ancienne."""
        rows = self._connection.execute(
            """
            SELECT * FROM operations ORDER BY started_at DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [_operation_from_row(row) for row in rows]

    def targets(self, operation_id: str, limit: int = 1000) -> list[TargetRecord]:
        """Cibles consignées pour une opération."""
        rows = self._connection.execute(
            """
            SELECT * FROM operation_targets WHERE operation_id = ? LIMIT ?
            """,
            (operation_id, limit),
        ).fetchall()
        return [
            TargetRecord(
                operation_id=row["operation_id"],
                path=row["path"],
                outcome=row["outcome"],
                reason=row["reason"],
                size_bytes=row["size_bytes"],
            )
            for row in rows
        ]

    def purge(self, *, older_than_days: float | None = None) -> int:
        """Purge manuelle du journal ; retourne le nombre d'opérations supprimées.

        Sans argument, le journal est **entièrement** vidé : la confirmation
        explicite relève de l'appelant.
        """
        if older_than_days is None:
            count = self._connection.execute("SELECT COUNT(*) FROM operations").fetchone()[0]
            self._connection.execute("DELETE FROM operation_targets")
            self._connection.execute("DELETE FROM operations")
        else:
            cutoff = (
                dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=older_than_days)
            ).isoformat()
            ids = [
                row[0]
                for row in self._connection.execute(
                    "SELECT operation_id FROM operations WHERE started_at < ?", (cutoff,)
                ).fetchall()
            ]
            for operation_id in ids:
                self._connection.execute(
                    "DELETE FROM operation_targets WHERE operation_id = ?", (operation_id,)
                )
            self._connection.execute("DELETE FROM operations WHERE started_at < ?", (cutoff,))
            count = len(ids)
        self._connection.commit()
        return int(count)

    def _ensure_version(self) -> None:
        row = self._connection.execute("SELECT version FROM schema_info").fetchone()
        if row is None:
            self._connection.execute(
                "INSERT INTO schema_info (version) VALUES (?)", (SCHEMA_VERSION,)
            )


def _operation_from_row(row: sqlite3.Row) -> OperationRecord:
    try:
        summary = json.loads(row["error_summary"] or "{}")
    except json.JSONDecodeError:
        summary = {}
    return OperationRecord(
        operation_id=row["operation_id"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        rule_identifier=row["rule_identifier"],
        rule_version=row["rule_version"],
        mode=row["mode"],
        status=row["status"],
        targets=row["targets"],
        processed=row["processed"],
        quarantined=row["quarantined"],
        failed=row["failed"],
        theoretical_bytes=row["theoretical_bytes"],
        reclaimed_bytes=row["reclaimed_bytes"],
        error_summary=summary,
    )


def default_audit_path() -> Path:
    """Emplacement par défaut du journal, dans les données utilisateur."""
    import os
    import sys

    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "NettOS" / "audit.sqlite3"


__all__ = [
    "SCHEMA_VERSION",
    "AuditLog",
    "OperationRecord",
    "TargetRecord",
    "default_audit_path",
]
