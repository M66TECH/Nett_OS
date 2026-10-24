# SPDX-License-Identifier: AGPL-3.0-or-later
"""Test d'intégration : l'interface minimale démarre hors écran.

Le test est ignoré si PySide6 n'est pas installé, afin que le moteur
reste testable dans un environnement sans interface graphique.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("PySide6.QtWidgets", reason="PySide6 non installé")

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from nettos.ui.app import build_application
from nettos.ui.main_window import MainWindow


def test_main_window_builds_offscreen() -> None:
    app = build_application(["nettos-gui"], language="fr")
    assert isinstance(app, QApplication)

    window = MainWindow()
    assert window.windowTitle() == "NettOS"
    assert window.centralWidget() is not None
    window.close()


def test_translations_load_for_both_languages() -> None:
    from nettos.ui.translations import detect_language, install_translations

    app = build_application(["nettos-gui"], language="en")
    assert app._nettos_language == "en"
    assert install_translations(app, "en") is True
    assert install_translations(app, "fr") is True

    assert detect_language("en") == "en"
    assert detect_language("fr") == "fr"
    assert detect_language("xx") in {"fr", "en"}
