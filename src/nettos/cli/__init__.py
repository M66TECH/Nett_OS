# SPDX-License-Identifier: AGPL-3.0-or-later
"""Mode ligne de commande headless (cahier des charges, section 2.3).

Les commandes s'appuient sur les mêmes services applicatifs que
l'interface graphique. Aucune confirmation implicite : le futur
``clean`` exigera un drapeau ``--confirm`` explicite.

Le point d'entrée public est ``nettos.cli.main:main`` (console script).
"""

from __future__ import annotations

__all__: list[str] = []
