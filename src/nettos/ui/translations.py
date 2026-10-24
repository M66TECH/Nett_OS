# SPDX-License-Identifier: AGPL-3.0-or-later
"""Chargement des traductions Qt depuis ``nettos/i18n``.

Tous les libellés passent par ``self.tr(...)`` dès le premier fichier
d'interface (section 8.3). Les fichiers ``.qm`` compilés sont livrés dans
le paquet ; en leur absence, les libellés source (français) restent
affichés.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QLibraryInfo, QLocale, QTranslator

SUPPORTED_LANGUAGES = ("fr", "en")
DEFAULT_LANGUAGE = "fr"


def translations_dir() -> Path:
    """Répertoire des fichiers de traduction du paquet."""
    return Path(__file__).resolve().parent / "i18n"


def detect_language(explicit: str | None = None) -> str:
    """Choisit la langue : explicite, sinon locale système, sinon défaut."""
    if explicit:
        code = explicit.split("_")[0].split("-")[0].lower()
        if code in SUPPORTED_LANGUAGES:
            return code

    system = QLocale.system().name()[:2].lower()
    if system in SUPPORTED_LANGUAGES:
        return system
    return DEFAULT_LANGUAGE


def install_translations(app, language: str) -> bool:
    """Installe le traducteur Qt pour ``language``.

    Retourne ``True`` si un fichier de traduction a été chargé. Les
    traductions natives de Qt (boutons standards) sont toujours chargées
    lorsqu'elles existent.
    """
    qt_dir = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
    loaded = False

    qt_translator = QTranslator(app)
    if qt_translator.load(f"qtbase_{language}", qt_dir):
        app.installTranslator(qt_translator)
        app._nettos_qt_translator = qt_translator

    app_translator = QTranslator(app)
    if app_translator.load(f"nettos_{language}", str(translations_dir())):
        app.installTranslator(app_translator)
        app._nettos_app_translator = app_translator
        loaded = True

    return loaded
