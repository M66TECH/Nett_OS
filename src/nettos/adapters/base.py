# SPDX-License-Identifier: AGPL-3.0-or-later
"""Contrat d'un adaptateur de plateforme."""

from __future__ import annotations

from abc import ABC, abstractmethod

from nettos.core.result import VolumeInfo


class PlatformAdapter(ABC):
    """Interface commune aux adaptateurs Linux et Windows.

    Les implémentations concrètes arriveront avec le scanner de stockage
    (phase 2). La phase 1 ne fixe que le contrat.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Identifiant court de la plateforme (``linux`` ou ``windows``)."""

    @abstractmethod
    def list_volumes(self) -> list[VolumeInfo]:
        """Retourne les volumes montés détectés."""
