# 0003 — Arborescence `src/` et découpage par couches

- Statut : acceptée
- Date : 2026-10-24

## Contexte

Le cahier des charges (sections 4.1 à 4.3) impose une architecture en couches avec
une règle vérifiable : le moteur doit fonctionner et se tester sans interface
graphique. Il propose une organisation par domaine sous `src/nettos` tout en
précisant qu'on ne crée un module que lorsqu'une fonctionnalité réelle le justifie.

## Options envisagées

1. **Layout plat** (`nettos/` à la racine) — simple, mais mélange tests et code et
   favorise les imports accidentels depuis le répertoire courant.
2. **Layout `src/`** — isole le paquet installable du reste du dépôt, oblige à
   tester la version installée/importable, standard moderne.
3. **Monolithe** — écarté : contredit la règle de testabilité du moteur sans Qt.

## Décision

Adopter le **layout `src/`** (`src/nettos/…`) et le découpage par couches :
`core`, `adapters`, `diagnostics`, `cleaners`, `security`, `services`,
`persistence`, `ui`, `cli`. Les modules vides portent une docstring qui justifie
leur existence et précise la phase qui les remplira.

## Conséquences

- `pyproject.toml` utilise `package-dir = {"" = "src"}` et
  `packages.find where = ["src"]`.
- Les tests ajoutent `src` au `sys.path` via `conftest.py` et `pythonpath` de
  pytest, ce qui permet de lancer la suite sans installation préalable.
- La règle 7 (moteur sans Qt) est vérifiée par construction : les tests unitaires
  et l'intégration CLI n'importent pas PySide6.
- Éviter un « squelette mort-né » : aucun module n'est créé sans fonctionnalité
  réelle. Les paquets sans logique à ce stade contiennent uniquement une
  docstring de cadrage.
