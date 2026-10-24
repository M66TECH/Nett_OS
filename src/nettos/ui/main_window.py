# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fenêtre principale minimale de NettOS (phase 1).

Elle se contente de prouver que l'application démarre sur Linux et
Windows, que l'architecture et les traductions sont en place. Le tableau
de bord complet arrive en phase 5.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QMainWindow, QVBoxLayout, QWidget

from nettos import __version__


class MainWindow(QMainWindow):
    """Fenêtre principale : affiche l'état du socle de l'application."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(self.tr("NettOS"))
        self.resize(880, 560)

        central = QWidget(self)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        title = QLabel(self.tr("NettOS"), central)
        title.setObjectName("titleLabel")
        title.setAlignment(Qt.AlignmentFlag.AlignLeft)
        font = title.font()
        font.setPointSize(22)
        font.setBold(True)
        title.setFont(font)

        subtitle = QLabel(
            self.tr("Diagnostic, maintenance et nettoyage système — lecture seule."),
            central,
        )
        subtitle.setWordWrap(True)

        version = QLabel(self.tr("Version {version}").format(version=__version__), central)

        status = QLabel(
            self.tr(
                "Le socle est en place : architecture documentée, "
                "tests et intégration continue. Le scanner de stockage "
                "arrive à la prochaine étape."
            ),
            central,
        )
        status.setWordWrap(True)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(version)
        layout.addSpacing(16)
        layout.addWidget(status)
        layout.addStretch(1)

        self.setCentralWidget(central)
        self.statusBar().showMessage(
            self.tr("Aucune analyse lancée. Aucune opération d'écriture disponible.")
        )
