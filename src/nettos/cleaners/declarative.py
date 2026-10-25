# SPDX-License-Identifier: AGPL-3.0-or-later
"""Base commune des nettoyeurs livrés avec l'application.

Un nettoyeur concret ne fait que deux choses : déclarer sa règle et fournir
ses racines. Toute la mécanique de simulation (exclusions, validation de
chemin, âge, plafond) vient de :class:`SimulationEngine`, testée une fois.

La règle est exposée en attribut de classe ``RULE`` : le registre doit
pouvoir l'inspecter **sans instancier** le nettoyeur, afin qu'un nettoyeur
refusé ne soit jamais construit.
"""

from __future__ import annotations

from pathlib import Path

from nettos.cleaners.base import BaseCleaner, SimulationResult
from nettos.cleaners.rules import CleanerRule
from nettos.cleaners.simulation import SimulationEngine


class DeclarativeCleaner(BaseCleaner):
    """Nettoyeur entièrement décrit par sa règle et ses racines."""

    #: Règle déclarative, obligatoirement fournie par la sous-classe.
    RULE: CleanerRule

    def __init__(self, *, engine: SimulationEngine | None = None) -> None:
        self._engine = engine or SimulationEngine(max_candidates=self.MAX_CANDIDATES)

    @property
    def rule(self) -> CleanerRule:
        """Règle déclarative de ce nettoyeur."""
        return self.RULE

    def roots(self) -> list[Path]:
        """Racines autorisées, fournies par la sous-classe."""
        raise NotImplementedError

    def simulate(self) -> SimulationResult:
        """Énumère les cibles sans aucun effet de bord."""
        return self._engine.simulate(self.RULE, self.roots())


__all__ = ["DeclarativeCleaner"]
