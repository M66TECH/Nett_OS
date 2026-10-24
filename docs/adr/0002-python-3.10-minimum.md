# 0002 — Python 3.10 comme version minimale

- Statut : acceptée
- Date : 2026-10-24
- Annule partiellement : cahier des charges v1.1, section 3.1 (qui visait Python 3.12)

## Contexte

Le cahier des charges v1.1 retient « Python 3.12 ou supérieur ». L'environnement
de développement initial (et la machine de référence du mainteneur) ne dispose que
de Python 3.10.11, installé via le Microsoft Store.

Exiger 3.12 aurait bloqué le démarrage du socle sans bénéfice fonctionnel
immédiat : aucun code prévu en Phase 1 n'utilise de fonction réservée à 3.12.

## Options envisagées

1. **Exiger 3.12** — conforme au document, mais impose une installation préalable
   et retarde la Phase 1.
2. **Cibler 3.10** — démarrage immédiat, compatibilité plus large, au prix d'un
   écart documentaire et de l'absence de fonctions récentes.
3. **Cibler 3.10 avec montée de version prévue** — démarre maintenant, relève la
   cible vers 3.12 une fois l'outillage en place.

## Décision

Adopter **Python 3.10** comme version minimale (`requires-python = ">=3.10"`).
Le code reste écrit pour être compatible 3.12 : `from __future__ import
annotations`, typage moderne, aucune API obsolète. Ruff cible `py310`, mypy aussi.

## Conséquences

- `pyproject.toml` déclare `>=3.10`.
- La CI teste sur les versions disponibles (3.10 et 3.12 sur les runners GitHub).
- Adopter 3.10 implique quelques contraintes : pas de `type` statement, pas de
  `match` en conditions de typage avancées, `collections.abc` au lieu de `typing`
  pour les génériques d'abstraction (déjà appliqué par Ruff UP035).
- La montée vers 3.12 (si décidée) fera l'objet d'un nouvel ADR, sans réécriture
  attendue : la base est déjà écrite pour cette cible.
- Le cahier des charges devra être aligné en section 3.1.
