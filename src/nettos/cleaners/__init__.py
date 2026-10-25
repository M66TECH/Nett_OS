# SPDX-License-Identifier: AGPL-3.0-or-later
"""Moteur de nettoyage : simuler, autoriser, exécuter.

La phase 3 fournit :

- le modèle déclaratif des règles (:mod:`nettos.cleaners.rules`) ;
- le contrat commun des nettoyeurs (:mod:`nettos.cleaners.base`) ;
- le moteur de simulation en lecture seule (:mod:`nettos.cleaners.simulation`) ;
- le registre explicite des règles livrées (:mod:`nettos.cleaners.registry`) ;
- les premières règles Linux et Windows.

**Aucune suppression n'est possible dans cette version.** ``execute()``
lève ``NotImplementedError`` : la phase 4 ajoutera simulation confirmée,
revalidation juste avant opération et quarantaine.
"""

from __future__ import annotations

from nettos.cleaners.base import (
    BaseCleaner,
    CandidateFile,
    CleanerStatus,
    RejectedFile,
    SimulationResult,
)
from nettos.cleaners.declarative import DeclarativeCleaner
from nettos.cleaners.registry import (
    CleanerRegistry,
    RegisteredCleaner,
    current_platform,
    default_registry,
)
from nettos.cleaners.rules import (
    CleanerRule,
    CleanTarget,
    Platform,
    RiskLevel,
)
from nettos.cleaners.simulation import SimulationEngine, matches_exclusion, matches_pattern

__all__ = [
    "BaseCleaner",
    "CandidateFile",
    "CleanTarget",
    "CleanerRegistry",
    "CleanerRule",
    "CleanerStatus",
    "DeclarativeCleaner",
    "Platform",
    "RegisteredCleaner",
    "RejectedFile",
    "RiskLevel",
    "SimulationEngine",
    "SimulationResult",
    "current_platform",
    "default_registry",
    "matches_exclusion",
    "matches_pattern",
]
