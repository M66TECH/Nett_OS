# SPDX-License-Identifier: AGPL-3.0-or-later
"""Amorçage de l'application Qt.

``build_application`` est séparé de ``main`` pour permettre aux tests
d'instancier la fenêtre hors de tout événement utilisateur.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from PySide6.QtWidgets import QApplication

from nettos.ui.main_window import MainWindow
from nettos.ui.translations import detect_language, install_translations


def build_application(
    argv: Sequence[str] | None = None,
    *,
    language: str | None = None,
) -> QApplication:
    """Crée (ou retourne) l'instance ``QApplication`` configurée.

    Qt impose une instance unique par processus : on réutilise
    l'instance existante si elle a déjà été créée (utile en tests).
    """
    instance = QApplication.instance()
    if isinstance(instance, QApplication):
        app = instance
    else:
        app = QApplication(list(argv) if argv is not None else sys.argv)

    app.setApplicationName("NettOS")
    app.setOrganizationName("M66TECH")
    app.setApplicationDisplayName("NettOS")

    selected = detect_language(language)
    install_translations(app, selected)
    app._nettos_language = selected  # type: ignore[attr-defined]
    return app


def main(argv: Sequence[str] | None = None) -> int:
    """Point d'entrée graphique."""
    parser = argparse.ArgumentParser(prog="nettos-gui")
    parser.add_argument(
        "--lang",
        default=None,
        metavar="LANGUE",
        help="Langue de l'interface (fr ou en).",
    )
    known, qt_args = parser.parse_known_args(argv)

    qt_argv = [sys.argv[0], *qt_args]
    app = build_application(qt_argv, language=known.lang)

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
