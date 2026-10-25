# SPDX-License-Identifier: AGPL-3.0-or-later
"""Contrat d'un adaptateur de plateforme."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from nettos.core.result import VolumeInfo


class PlatformAdapter(ABC):
    """Interface commune aux adaptateurs Linux et Windows.

    Le cœur ne teste jamais ``sys.platform`` : il interroge l'adaptateur.
    Chaque méthode est en lecture seule.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Identifiant court de la plateforme (``linux`` ou ``windows``)."""

    @abstractmethod
    def list_volumes(self) -> list[VolumeInfo]:
        """Retourne les volumes montés détectés, triés par point de montage."""

    @abstractmethod
    def user_cache_dir(self) -> Path:
        """Répertoire racine des caches utilisateur de la plateforme."""

    @abstractmethod
    def temp_dir(self) -> Path:
        """Répertoire temporaire de l'utilisateur."""
