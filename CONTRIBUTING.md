# Contribuer à NettOS

Merci de l'intérêt porté au projet. Ce guide résume les règles de contribution.

## Avant de proposer une fonctionnalité

Le périmètre du MVP est fixé par le cahier des charges (section 2.1). Une idée
doit être évaluée à l'aune de ce périmètre et des non-objectifs permanents
(section 1.4). Dans le doute, ouvrir d'abord une issue de discussion.

## Règles d'or

1. Le moteur doit rester testable **sans Qt**. Les tests unitaires et l'intégration
   CLI n'importent jamais PySide6.
2. Toute modification touchant la sécurité nécessite un test dédié.
3. Une décision structurante produit un **ADR** dans `docs/adr/`.
4. Chaque fichier source porte l'en-tête `SPDX-License-Identifier: AGPL-3.0-or-later`.

## Environnement

```bash
python -m venv .venv
# Linux : source .venv/bin/activate
# Windows : .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Vérifications avant un pull request

```bash
ruff check .
ruff format --check .
mypy
pytest -q
```

La CI GitHub Actions exécute ces contrôles sur **Linux et Windows**, sur Python
3.10 et 3.12. Un pull request n'est fusionné que si ces contrôles passent.

## Convention de branches et de commits

Branches explicites :

```
feat/storage-scanner
test/path-security
fix/scan-cancellation
```

Messages de commit clairs et à l'impératif. Une pull request présente :

- le problème résolu ;
- les choix techniques ;
- les tests effectués (et leur résultat) ;
- les limites restantes.

## Traductions

Tous les libellés d'interface passent par `self.tr(...)`. Pour mettre à jour les
traductions :

```bash
# extraire les chaînes (nécessite pyside6-lupdate)
pyside6-lupdate src/nettos/ui/*.py -ts src/nettos/ui/i18n/nettos_fr.ts
pyside6-lupdate src/nettos/ui/*.py -ts src/nettos/ui/i18n/nettos_en.ts

# compiler vers .qm
pyside6-lrelease src/nettos/ui/i18n/nettos_fr.ts
pyside6-lrelease src/nettos/ui/i18n/nettos_en.ts
```

Les fichiers `.qm` sont versionnés : ils sont livrés avec l'application.

## Licence de contribution

En proposant du code, vous acceptez sa distribution sous AGPL-3.0-or-later.
