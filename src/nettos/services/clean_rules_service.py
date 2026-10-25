# SPDX-License-Identifier: AGPL-3.0-or-later
"""Service applicatif des règles de nettoyage.

Expose le registre aux interfaces (Qt et ligne de commande) sans dupliquer
de logique. **Aucune suppression** : seules la liste des règles et la
simulation sont disponibles en phase 3.
"""

from __future__ import annotations

from nettos.cleaners import (
    CleanerRegistry,
    Platform,
    RegisteredCleaner,
    RiskLevel,
    default_registry,
)
from nettos.cleaners.base import SimulationResult


class CleanRulesService:
    """Relit, filtre et simule les règles sans jamais exécuter."""

    def __init__(self, registry: CleanerRegistry | None = None) -> None:
        self._registry = registry or default_registry()

    @property
    def registry(self) -> CleanerRegistry:
        """Registre sous-jacent."""
        return self._registry

    def list_rules(self, *, risk_at_least: RiskLevel | None = None) -> list[RegisteredCleaner]:
        """Entrées du registre, éventuellement filtrées par niveau de risque.

        Le filtre porte sur ``risk >= risk_at_least`` : demander ``MODERATE``
        inclut ``HIGH``, pour pouvoir afficher « tout ce qui est risqué ».
        """
        entries = self._registry.entries()
        if risk_at_least is None:
            return entries
        return [
            entry
            for entry in entries
            if entry.rule is not None and entry.rule.risk >= risk_at_least
        ]

    def simulate(self, identifier: str) -> SimulationResult:
        """Simule une règle active ; lève si la règle n'est pas exécutable."""
        return self._registry.instantiate(identifier).simulate()

    def as_dict(self, entries: list[RegisteredCleaner]) -> list[dict[str, object]]:
        """Sérialise les règles pour ``nettos rules --json``."""
        payload: list[dict[str, object]] = []
        for entry in entries:
            rule = entry.rule
            if rule is None:
                payload.append(
                    {
                        "identifier": None,
                        "status": entry.status.value,
                        "reason": entry.reason,
                    }
                )
                continue
            payload.append(
                {
                    "identifier": rule.identifier,
                    "title": rule.title,
                    "version": rule.version,
                    "risk": rule.risk.label,
                    "platforms": sorted(platform.value for platform in rule.platforms),
                    "targets": [target.pattern for target in rule.targets],
                    "excluded": list(rule.excluded),
                    "status": entry.status.value,
                    "status_reason": entry.reason,
                    "requires_admin": rule.requires_admin,
                    "reviewed_on": rule.reviewed_on.isoformat() if rule.reviewed_on else None,
                    "is_stale": rule.is_stale,
                }
            )
        return payload

    def simulation_as_dict(self, result: SimulationResult) -> dict[str, object]:
        """Sérialise une simulation pour ``nettos plan --json``."""
        return {
            "schema": "nettos.plan/1",
            "rule": result.rule_identifier,
            "file_count": result.file_count,
            "total_bytes": result.total_bytes,
            "rejected_count": result.rejected_count,
            "truncated": result.truncated,
            "missing_roots": list(result.missing_roots),
            "candidates": [
                {
                    "path": candidate.path,
                    "size_bytes": candidate.size_bytes,
                    "age_days": candidate.age_days,
                }
                for candidate in result.candidates
            ],
            "rejected": [
                {"path": rejected.path, "reason": rejected.reason, "kind": rejected.kind.value}
                for rejected in result.rejected
            ],
        }


def platform_from_name(name: str) -> Platform:
    """Convertit ``linux``/``windows`` en :class:`Platform`."""
    return Platform.parse(name)


__all__ = ["CleanRulesService", "platform_from_name"]
