# 0001 — Licence AGPL-3.0 plutôt que GPL-3.0

- Statut : acceptée
- Date : 2026-10-24
- Annule partiellement : cahier des charges v1.1, section 1.5 (qui retenait GPL-3.0)

## Contexte

Le cahier des charges v1.1 fixe la licence GNU GPL-3.0 pour NettOS, au motif qu'un
logiciel qui examine le disque et supprime des fichiers doit rester auditable et
sous copyleft fort.

Lors de l'initialisation du dépôt `github.com/M66TECH/Nett_OS`, un fichier
`LICENSE` contenant la GNU **Affero** General Public License v3.0 (AGPL-3.0) a été
déposé dans le commit initial. La direction du projet a choisi de le conserver.

## Options envisagées

1. **Remplacer par GPL-3.0** — conforme au cahier des charges, mais supprime un
   fichier déjà publié et réécrit une décision de gouvernance prise au dépôt.
2. **Conserver AGPL-3.0** — sur-ensemble de la GPL-3.0 du point de vue des
   obligations : ajoute la clause réseau (section 13 de l'AGPL).
3. **Reporter la décision** — laisse une ambiguïté entre le document et le dépôt.

## Décision

Adopter **AGPL-3.0-or-later**. Le fichier `LICENSE` existant est conservé tel quel.
Tous les fichiers sources portent l'en-tête `SPDX-License-Identifier:
AGPL-3.0-or-later`.

## Conséquences

- Le cahier des charges devra être corrigé en section 1.5 lors de la prochaine
  révision documentaire (ce point est le seul écart de licence).
- Toute dépendance doit rester compatible avec l'AGPL-3.0. En particulier, les
  licences de PySide6 (LGPL/GPL) restent compatibles dans le cadre d'une
  distribution sous AGPL, sous réserve de respecter les obligations Qt.
- Si un jour un service réseau expose NettOS, la section 13 de l'AGPL impose de
  fournir le code source aux utilisateurs du réseau : cohérent avec la promesse
  de transparence du projet.
- Le README et `docs/` mentionnent AGPL-3.0 comme licence effective.
