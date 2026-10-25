# SPDX-License-Identifier: AGPL-3.0-or-later
"""Contrôle d'annulation coopératif pour les opérations longues.

Le scanner et les futurs moteurs vérifient régulièrement ce jeton afin
que l'interface puisse annuler une analyse sans bloquer (section 4.2,
règle 5). L'annulation est toujours coopérative : aucun thread n'est tué.
"""

from __future__ import annotations

import threading

from nettos.core.errors import OperationCancelledError


class CancellationToken:
    """Jeton d'annulation observable et réutilisable."""

    __slots__ = ("_event",)

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        """Demande l'annulation ; idempotent."""
        self._event.set()

    @property
    def is_cancelled(self) -> bool:
        """``True`` dès qu'une annulation a été demandée."""
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        """Lève :class:`OperationCancelledError` si l'annulation est demandée."""
        if self._event.is_set():
            raise OperationCancelledError("Opération annulée par l'utilisateur.")

    def reset(self) -> None:
        """Remet le jeton à l'état initial, pour réutilisation."""
        self._event.clear()
