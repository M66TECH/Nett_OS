# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exécution contrôlée d'un nettoyage (cahier des charges, section 6.1).

Le pipeline est strictement ordonné et chaque point de décision est
**bloquant** :

1. **simulation** — obligatoire, produit la liste des cibles et l'estimation ;
2. **décision** — sans ``confirm`` explicite, aucune suppression n'a lieu ;
3. **revalidation** — chaque cible est revalidée juste avant l'opération
   (identité, taille, date, liens, périmètre) ;
4. **action** — mise en quarantaine si possible, sinon suppression signalée
   comme irréversible ;
5. **mesure** — l'espace réellement récupéré est calculé, distinct de
   l'estimation théorique ;
6. **journalisation** — l'opération, ses règles et ses erreurs sont
   consignées, jamais le contenu des fichiers.

Une cible revalidée hors autorisation est **ignorée et journalisée** ; le
reste du lot continue (comportement imposé par la section 6.1).
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from nettos.cleaners.base import BaseCleaner, SimulationResult
from nettos.cleaners.quarantine import Quarantine, QuarantineEntry
from nettos.cleaners.rules import CleanerRule
from nettos.core.errors import PathOutsideAuthorizedRootError
from nettos.core.result import ErrorKind
from nettos.persistence.audit_log import AuditLog, TargetRecord
from nettos.security.path_policy import is_within_root
from nettos.security.revalidation import (
    RevalidationOutcome,
    TargetSnapshot,
    revalidate,
)

MAX_TARGETS_PER_RUN = 50_000
"""Garde-fou contre une opération massive accidentelle (section 5.3)."""


class ExecutionMode(str, Enum):
    """Mode d'exécution d'un nettoyage."""

    DRY_RUN = "dry-run"
    """Simulation seule : aucune écriture, aucune quarantaine."""

    EXECUTE = "execute"
    """Exécution réelle, après confirmation explicite."""


class TargetOutcome(str, Enum):
    """Issue du traitement d'une cible."""

    PLANNED = "planned"
    QUARANTINED = "quarantined"
    DELETED = "deleted"
    REJECTED = "rejected"
    FAILED = "failed"


@dataclass(slots=True)
class TargetResult:
    """Résultat détaillé pour une cible."""

    path: str
    outcome: TargetOutcome
    reason: str = ""
    size_bytes: int = 0
    kind: ErrorKind = ErrorKind.OTHER


@dataclass(slots=True)
class ExecutionReport:
    """Rapport d'exécution : estimation théorique **et** mesure réelle."""

    operation_id: str
    rule_identifier: str
    rule_version: str
    mode: ExecutionMode
    status: str = "completed"
    theoretical_bytes: int = 0
    reclaimed_bytes: int = 0
    results: list[TargetResult] = field(default_factory=list)
    error_summary: dict[str, int] = field(default_factory=dict)
    duration_seconds: float = 0.0
    confirmation_provided: bool = False

    @property
    def processed(self) -> int:
        """Cibles réellement traitées (mises en quarantaine ou supprimées)."""
        return sum(
            1
            for result in self.results
            if result.outcome in {TargetOutcome.QUARANTINED, TargetOutcome.DELETED}
        )

    @property
    def failed(self) -> int:
        """Cibles en échec."""
        return sum(1 for result in self.results if result.outcome is TargetOutcome.FAILED)

    @property
    def rejected(self) -> int:
        """Cibles refusées par la revalidation."""
        return sum(1 for result in self.results if result.outcome is TargetOutcome.REJECTED)

    @property
    def quarantined(self) -> int:
        """Cibles placées en quarantaine."""
        return sum(1 for result in self.results if result.outcome is TargetOutcome.QUARANTINED)

    @property
    def irreversible(self) -> int:
        """Cibles supprimées sans possibilité de restauration."""
        return sum(1 for result in self.results if result.outcome is TargetOutcome.DELETED)

    @property
    def space_difference(self) -> int:
        """Écart entre estimation et espace réellement récupéré.

        Positif quand la taille théorique dépasse le gain réel : liens
        physiques, compression ou fichiers encore ouverts (section 6.1).
        """
        return self.theoretical_bytes - self.reclaimed_bytes


class CleanExecutionService:
    """Applique le pipeline complet pour une règle donnée."""

    MAX_TARGETS_DEFAULT = MAX_TARGETS_PER_RUN

    def __init__(
        self,
        *,
        quarantine: Quarantine,
        audit: AuditLog | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._quarantine = quarantine
        self._audit = audit
        self._clock = clock or time.time

    def execute(
        self,
        cleaner: BaseCleaner,
        *,
        mode: ExecutionMode,
        confirm: bool = False,
        simulation: SimulationResult | None = None,
        max_targets: int = MAX_TARGETS_PER_RUN,
    ) -> ExecutionReport:
        """Exécute (ou simule) le nettoyage d'un nettoyeur.

        ``confirm`` est **obligatoire** pour le mode ``EXECUTE`` : ce n'est
        pas une politique, c'est une garde. Sans lui, le rapport est produit
        avec le statut ``needs_confirmation`` et **rien** n'est touché.
        """
        started = self._clock()
        planned = simulation if simulation is not None else cleaner.simulate()
        rule = cleaner.rule

        report = ExecutionReport(
            operation_id=uuid.uuid4().hex,
            rule_identifier=rule.identifier,
            rule_version=rule.version,
            mode=mode,
            theoretical_bytes=planned.total_bytes,
            confirmation_provided=confirm,
        )

        candidates = planned.candidates
        if len(candidates) > max_targets:
            candidates = candidates[:max_targets]
            report.status = "truncated"

        if mode is ExecutionMode.DRY_RUN:
            report.results = [
                TargetResult(
                    path=candidate.path,
                    outcome=TargetOutcome.PLANNED,
                    size_bytes=candidate.size_bytes,
                    reason="simulation : aucun fichier touché",
                )
                for candidate in candidates
            ]
            report.duration_seconds = self._clock() - started
            return report

        if not confirm:
            report.status = "needs_confirmation"
            report.results = [
                TargetResult(
                    path=candidate.path,
                    outcome=TargetOutcome.PLANNED,
                    size_bytes=candidate.size_bytes,
                    reason="confirmation explicite absente : aucun fichier touché",
                )
                for candidate in candidates
            ]
            report.duration_seconds = self._clock() - started
            return report

        roots = [Path(os.path.realpath(root)) for root in cleaner.roots()]
        self._start_audit(report, len(candidates))

        for candidate in candidates:
            report.results.extend(self._process_candidate(candidate, rule, roots))

        report.duration_seconds = self._clock() - started
        self._finalize_audit(report)
        return report

    def _process_candidate(
        self,
        candidate: object,
        rule: CleanerRule,
        roots: list[Path],
    ) -> list[TargetResult]:
        """Revalide puis traite une cible ; retourne ses résultats détaillés.

        Point critique de sécurité : la référence de comparaison est
        l'identité observée **pendant la simulation** (``CandidateFile``),
        jamais une relecture faite ici. Relire les métadonnées au moment de
        l'action reviendrait à comparer l'état présent à lui-même et à
        annuler toute protection contre le remplacement entre simulation et
        exécution.
        """
        from nettos.cleaners.base import CandidateFile

        assert isinstance(candidate, CandidateFile)
        path = candidate.path
        snapshot = TargetSnapshot(
            path=path,
            size_bytes=candidate.size_bytes,
            mtime=candidate.modified_at,
            file_id=candidate.file_id,
        )

        root = self._root_for(Path(path), roots)
        if root is None:
            return [
                TargetResult(
                    path=path,
                    outcome=TargetOutcome.REJECTED,
                    reason="cible hors du périmètre autorisé",
                )
            ]

        outcome = self._do_revalidate(snapshot, root)
        if not outcome.accepted:
            return [
                TargetResult(
                    path=path,
                    outcome=TargetOutcome.REJECTED,
                    reason=outcome.reason,
                    kind=outcome.kind,
                )
            ]
        if outcome.file_descriptor is not None:
            os.close(outcome.file_descriptor)

        return self._quarantine_or_delete(snapshot, rule, candidate.size_bytes)

    def _do_revalidate(self, snapshot: TargetSnapshot, root: Path) -> RevalidationOutcome:
        """Revalide en convertissant une sortie de périmètre en rejet explicite."""
        try:
            return revalidate(snapshot, root=root, keep_open=False)
        except PathOutsideAuthorizedRootError as exc:
            return RevalidationOutcome.reject(str(exc))

    def _quarantine_or_delete(
        self,
        snapshot: TargetSnapshot,
        rule: CleanerRule,
        size_bytes: int,
    ) -> list[TargetResult]:
        """Déplace en quarantaine ; en cas d'échec, supprime en le signalant."""
        source = Path(snapshot.path)
        try:
            entry: QuarantineEntry = self._quarantine.store(
                source,
                rule_identifier=rule.identifier,
                rule_version=rule.version,
                size_bytes=size_bytes,
                original_path=snapshot.path,
            )
        except OSError as exc:
            note = f"quarantaine impossible : {exc}"
            return self._delete_directly(snapshot, rule, size_bytes, note)

        note = f"entrée {entry.entry_id}"
        if entry.state != "quarantined":
            note = f"entrée {entry.entry_id} (quarantaine partielle)"
        return [
            TargetResult(
                path=snapshot.path,
                outcome=TargetOutcome.QUARANTINED,
                size_bytes=size_bytes,
                reason=note,
            )
        ]

    def _delete_directly(
        self,
        snapshot: TargetSnapshot,
        rule: CleanerRule,
        size_bytes: int,
        note: str,
    ) -> list[TargetResult]:
        """Suppression irréversible, seulement après revalidation réussie."""
        try:
            os.unlink(snapshot.path)
        except OSError as exc:
            return [
                TargetResult(
                    path=snapshot.path,
                    outcome=TargetOutcome.FAILED,
                    reason=str(exc),
                    kind=ErrorKind.IO_ERROR,
                )
            ]

        return [
            TargetResult(
                path=snapshot.path,
                outcome=TargetOutcome.DELETED,
                size_bytes=size_bytes,
                reason=note,
            )
        ]

    @staticmethod
    def _root_for(path: Path, roots: list[Path]) -> Path | None:
        """Retourne la racine autorisée contenant ``path``, s'il en existe une."""
        resolved = Path(os.path.realpath(path))
        for root in roots:
            if is_within_root(resolved, root):
                return root
        return None

    # ----------------------------------------------------------------- audit

    def _start_audit(self, report: ExecutionReport, targets: int) -> None:
        if self._audit is None:
            return
        self._audit.start_operation(
            operation_id=report.operation_id,
            rule_identifier=report.rule_identifier,
            rule_version=report.rule_version,
            mode=report.mode.value,
            targets=targets,
            theoretical_bytes=report.theoretical_bytes,
        )

    def _finalize_audit(self, report: ExecutionReport) -> None:
        if self._audit is None:
            report.reclaimed_bytes = self._measured_reclaimed(report)
            return
        reclaimed = self._measured_reclaimed(report)
        report.reclaimed_bytes = reclaimed
        report.error_summary = _summarize_errors(report.results)
        records = [
            TargetRecord(
                operation_id=report.operation_id,
                path=result.path,
                outcome=result.outcome.value,
                reason=result.reason,
                size_bytes=result.size_bytes,
            )
            for result in report.results
        ]
        if records:
            self._audit.record_targets(records)
        self._audit.finish_operation(
            report.operation_id,
            status=report.status,
            processed=report.processed,
            quarantined=report.quarantined,
            failed=report.failed,
            reclaimed_bytes=reclaimed,
            error_summary=report.error_summary,
        )

    @staticmethod
    def _measured_reclaimed(report: ExecutionReport) -> int:
        """Espace réellement récupéré : seules les cibles traitées comptent."""
        return sum(
            result.size_bytes
            for result in report.results
            if result.outcome in {TargetOutcome.QUARANTINED, TargetOutcome.DELETED}
        )


def _summarize_errors(results: list[TargetResult]) -> dict[str, int]:
    """Compte les erreurs par catégorie, sans jamais les masquer."""
    summary: dict[str, int] = {}
    for result in results:
        if result.outcome in {TargetOutcome.REJECTED, TargetOutcome.FAILED}:
            key = result.kind.value if result.kind else "other"
            summary[key] = summary.get(key, 0) + 1
    return summary


__all__ = [
    "MAX_TARGETS_PER_RUN",
    "CleanExecutionService",
    "ExecutionMode",
    "ExecutionReport",
    "TargetOutcome",
    "TargetResult",
]
