# SPDX-License-Identifier: AGPL-3.0-or-later
"""Interface graphique Qt (PySide6 / Qt Widgets).

Présente les résultats et recueille les décisions de l'utilisateur.
Elle ne supprime jamais directement de fichier et n'accède pas au
système de fichiers hors services applicatifs (section 4.1).

Le point d'entrée graphique est ``nettos.ui.app:main`` (gui-script).
"""

from __future__ import annotations

__all__: list[str] = []
